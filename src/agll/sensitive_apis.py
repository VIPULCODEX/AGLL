"""Sensitive Android API patterns used by the Stage 1 score.

The list is hand-curated from Android's permission categories and from the
behavior taxonomy in MalLoc's prompts (SMS and call abuse, privacy stealing,
aggressive advertising, tricky behavior). It has not been validated against a
labeled dataset.

A method is sensitive if its full name, `Lclass/Name;->methodName`, contains
any pattern below as a substring.
"""

SENSITIVE_APIS: dict[str, list[str]] = {
    "sms_call": [
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
        "Landroid/telephony/SmsManager;->sendDataMessage",
        "Landroid/provider/Telephony$Sms",
        "Landroid/telephony/TelephonyManager;->listen",
        "Landroid/telecom/TelecomManager;->placeCall",
        "Landroid/content/Intent;->ACTION_CALL",
    ],
    "device_identifiers": [
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/telephony/TelephonyManager;->getSubscriberId",
        "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
        "Landroid/telephony/TelephonyManager;->getLine1Number",
        "Landroid/provider/Settings$Secure;->getString",
        "Landroid/net/wifi/WifiInfo;->getMacAddress",
        "Landroid/bluetooth/BluetoothAdapter;->getAddress",
    ],
    "location": [
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Landroid/location/LocationManager;->requestLocationUpdates",
        "Lcom/google/android/gms/location/FusedLocationProviderClient;->getLastLocation",
        "Lcom/google/android/gms/location/FusedLocationProviderClient;->requestLocationUpdates",
    ],
    "contacts_and_pii": [
        "Landroid/content/ContentResolver;->query",
        "Landroid/provider/ContactsContract",
        "Landroid/provider/CallLog",
        "Landroid/accounts/AccountManager;->getAccounts",
    ],
    "network_exfil": [
        "Ljava/net/HttpURLConnection;->connect",
        "Ljava/net/URL;->openConnection",
        "Lokhttp3/Call;->execute",
        "Lokhttp3/OkHttpClient;->newCall",
        "Ljava/net/Socket;-><init>",
        "Lorg/apache/http/client/HttpClient;->execute",
    ],
    "dynamic_code_and_reflection": [
        "Ldalvik/system/DexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>",
        "Ljava/lang/reflect/Method;->invoke",
        "Ljava/lang/Class;->forName",
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/ProcessBuilder;->start",
    ],
    "app_hiding_and_persistence": [
        "Landroid/content/pm/PackageManager;->setComponentEnabledSetting",
        "Landroid/app/admin/DevicePolicyManager",
        "Landroid/content/pm/PackageManager;->HIDE",
        "Landroid/content/BroadcastReceiver;->setResultData",
    ],
    "sensor_and_media": [
        "Landroid/media/MediaRecorder;->start",
        "Landroid/hardware/Camera;->open",
        "Landroid/hardware/camera2/CameraManager;->openCamera",
    ],
    "file_and_storage": [
        "Landroid/os/Environment;->getExternalStorageDirectory",
        "Ljava/io/FileOutputStream;-><init>",
        "Landroid/content/Context;->openFileOutput",
    ],
}


def flatten_patterns() -> list[str]:
    return [pattern for group in SENSITIVE_APIS.values() for pattern in group]


def category_for(full_name: str) -> str | None:
    for category, patterns in SENSITIVE_APIS.items():
        for pattern in patterns:
            if pattern in full_name:
                return category
    return None


def is_sensitive(full_name: str) -> bool:
    return category_for(full_name) is not None
