# AGLL: Analysis-Guided LLM Localization

AGLL finds the few malicious methods hidden in an Android application. Existing
LLM-based tools such as MalLoc and RAML let the model decide which code to look
at first. AGLL reverses that order: a static call-graph analysis picks a small
shortlist of suspicious methods, and only then does an LLM read them. Each
verdict has to quote the API calls it relies on, and those quotes are checked
against the method's real bytecode.

This repository holds the implementation, the two test applications built for
the paper, and the result files behind its tables. The paper is
*Analysis-Guided LLM Localization: Static-Analysis-First Candidate Narrowing for
Malicious Payload Detection in Android Applications* (Sharma, Hooda, Kumar).

## How it works

| Stage | What it does | Code |
|---|---|---|
| 1. Structural narrowing | Builds the call graph with androguard and scores every method of the app's own package from three signals: distance to a sensitive API, distance from an entry point, and cyclomatic complexity. No LLM is involved. | `src/agll/callgraph.py`, `suspicion.py`, `sensitive_apis.py`, `run_stage1.py` |
| 2. LLM interpretation | Sends the smali body of each shortlisted method to a local model, one prompt per method, and asks for a verdict, a behavior category, a confidence value and verbatim evidence. | `src/agll/llm_interpret.py`, `run_stage2.py` |
| 3. Grounding check | Checks that every API reference quoted as evidence appears in the method body. References that do not are reported as ungrounded. | `src/agll/llm_interpret.py` (`grounding_check`) |
| Calibration (optional) | Fuses four confidence signals with a logistic model and derives an accept-or-review threshold from Elkan's cost rule. | `src/agll/calibration.py`, `run_calibration.py` |

The default Stage 1 weights are 0.7 for the sensitive-API signal, 0.1 for the
entry-point signal and 0.2 for complexity. `run_weight_ablation.py` recomputes
the ranking under other weights from the cached scores.

## Repository layout

```
.
├── src/agll/                  library code (stages 1-3 and calibration)
├── run_stage1.py              Stage 1: rank the methods of an APK
├── run_stage2.py              Stages 2 and 3: interpret the shortlist and score it
├── run_calibration.py         confidence signals and logistic fit
├── run_weight_ablation.py     Stage 1 weight grid search
├── fixtures/                  source of the two test applications
│   ├── SyntheticMalApp/
│   └── RealisticMalApp/
├── results/                   output of the scripts above
│   └── <app>_<stage>_<artifact>.json
├── reproduced/                output of the MalLoc and RAML baselines
│   ├── malloc/<app>/behavior_<id>/
│   └── raml/realistic_malapp/
├── requirements.txt
└── LICENSE
```

Result files follow one pattern: `malapp`, `synthetic` or `realistic`, then the
stage (`stage1`, `stage2`), then `scores`, `interactions` or `results`. A
`_top10` suffix marks the run that used the top 10% instead of the top 5%.

## Requirements

- Python 3.10 or newer (the code uses `X | Y` type hints; the results were
  produced with Python 3.14)
- `pip install -r requirements.txt`
- [Ollama](https://ollama.com) with the two models used in the paper:

```
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
ollama pull qwen2.5:1.5b
```

The second model is only needed for the ensemble signal in the calibration step.

## Running the pipeline

The scripts read some inputs from a checkout of MalLoc's replication package,
which is not redistributed here (see `reproduced/NOTICE.txt`). Clone it next to
this repository so that `../MalLoc/0_Data/` exists:

```
<workspace>/
├── AGLL/        this repository
└── MalLoc/      https://github.com/Trustworthy-Software/MalLoc
```

The default paths in `run_calibration.py` and `run_weight_ablation.py` assume
this layout. They expect the ground-truth files `MalApp_1_9_11_groundtruth.json`,
`SyntheticMalApp_groundtruth.json` and `RealisticMalApp_groundtruth.json` in
`MalLoc/0_Data/APKs/`. The first belongs to MalLoc. The other two are the
fixture manifests in `fixtures/` converted to MalLoc's format and are not part
of this repository.

**Stage 1.** Rank the methods of an APK and compare the ranking with the ground truth:

```
python3 run_stage1.py --apk app.apk \
    --groundtruth app_groundtruth.json \
    --package 'Lorg/example/app/' \
    --out app_stage1_scores.json
```

Loading the largest application takes about two minutes, most of it spent in
androguard.

**Stages 2 and 3.** Interpret the shortlist. `--smali` is an apktool output
directory for the same APK, and `--top-pct` is the fraction of the ranking to
send to the model:

```
python3 run_stage2.py --scores results/app_stage1_scores.json \
    --gt app_groundtruth.json --smali app_apktool_output/ \
    --top-pct 0.05 --behavior-ids 1,9,11 \
    --interactions-out app_stage2_interactions.json \
    --results-out app_stage2_results.json
```

Useful flags: `--dry-run` prints the shortlist and one prompt without calling
the model, `--resume` skips ranks that already have a saved interaction, and
`--judge-only` re-scores saved interactions, which is how the committed results
can be checked without Ollama.

**Calibration and weight ablation.** Both run from the repository root:

```
python3 run_calibration.py
python3 run_weight_ablation.py
```

`run_calibration.py` reuses the signals already stored in
`results/calibration_detail.json`, so with the committed file it only refits
the model and needs no LLM.

## Results

Method-level results, with the same local 7B model for every system (the
`MalLoc` rows are the reproduced baseline, not MalLoc's published numbers):

| Application | System | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| MalApp_1_9_11 | MalLoc | 7 | 31 | 5 | 0.184 | 0.583 | 0.280 |
| | AGLL | 7 | 3 | 5 | 0.700 | 0.583 | 0.636 |
| RealisticMalApp | MalLoc | 8 | 6 | 0 | 0.571 | 1.000 | 0.727 |
| | RAML | 8 | 9 | 0 | 0.471 | 1.000 | 0.640 |
| | AGLL | 7 | 4 | 1 | 0.636 | 0.875 | 0.737 |
| SyntheticMalApp | MalLoc | 0 | 5 | 8 | 0.000 | 0.000 | 0.000 |
| | AGLL | 0 | 1 | 8 | 0.000 | 0.000 | 0.000 |

The AGLL rows are in `results/*_stage2_results.json`. The baseline rows were scored from the files in `reproduced/`.

## Limitations

- Everything ran on one local 7B model. The reproduced MalLoc baseline scores
  well below MalLoc's published results, which used larger models, so these
  numbers say nothing about how AGLL compares with MalLoc under a stronger model.
- The evaluation covers one 366-method demonstration application and two small
  applications of 32 and 35 methods. It is not a real-world malware corpus.
- The Stage 1 weights were chosen by a grid search over the same three
  applications, without a held-out set.
- The calibration fit uses 51 candidates and is evaluated on the data it was
  fit on. Treat it as a demonstration of the mechanism, not a validated model.

## Test applications

`fixtures/SyntheticMalApp` and `fixtures/RealisticMalApp` are controlled
research fixtures, not deployable malware. Neither declares SMS, accessibility,
overlay or network permissions. See `fixtures/README.md` for how they were built
and what they contain.

## Baseline artifacts

`reproduced/` contains only the output of running MalLoc and RAML on the
applications above (logs, per-behavior interaction records, spreadsheets, and
one RAML result file), not their source code. Their code and terms are
described in `reproduced/NOTICE.txt`.

## License

AGLL's own code and the result files are released under the MIT License, see
`LICENSE`. MalLoc and RAML are separate projects with their own terms.
