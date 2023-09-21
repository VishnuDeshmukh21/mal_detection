from django.shortcuts import render

# Create your views here.
import json
import os
import pickle
import pandas as pd
import numpy as np
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
import numpy as np
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt


# Define the MalwarePredictor class to encapsulate the prediction logic
import pickle
import numpy as np
import pandas as pd

class MalwarePredictor:
    def __init__(self, model_path):
        self.model = pickle.load(open(model_path, "rb"))

    def extract_features(self, data):
        static_features = {
            'api_call': data.get('APICall'),
            'permission': data.get('Permission'),
            'url': data.get('URL'),
            'provider': data.get('Provider'),
            'feature': data.get('Feature'),
            'intent': data.get('Intent'),
            'activity': data.get('Activity'),
            'call': data.get('Call'),
            'service_receiver': data.get('ServiceReceiver'),
            'real_permission': data.get('RealPermission')
        }

        for i, value in static_features.items():
            if not value:
                static_features[i] =""
                #raise ValueError(f"Missing feature: '{i}' is not present in the data.")

        ext_data = pd.DataFrame(static_features, index=[0])
        extracted_data = []
        for i in range(ext_data.shape[1]):
            test_data = ext_data.values[:, i]
            tfidf = pickle.load(open("static/tfidf_col{}.pkl".format(i), "rb"))
            test_tfidf = tfidf.transform(test_data).todense()

            if len(extracted_data) == 0:
                extracted_data = test_tfidf
            else:
                extracted_data = np.concatenate((extracted_data, test_tfidf), axis=1)

        return extracted_data

    def extract_features_test(self, data):
        X_test = []
        models = []
        # iterate over each column
        for i in range(data.shape[1]):
            test_data = data[:, i]
            tfidf = pickle.load(open("static/tfidf_col{}.pkl".format(i), "rb"))

            try:
                test_tfidf = tfidf.transform(test_data).todense()
            except Exception as e:
                error_message = "Error transforming data for column {}: {}".format(i, str(e))
                # Raise an exception with the error message
                raise ValueError(error_message)

            if len(X_test) == 0:
                X_test = test_tfidf
            else:
                X_test = np.concatenate((X_test, test_tfidf), axis=1)
            models.append(tfidf)

        return X_test, models

    def predict(self, X_test):
        # Prediction logic...
        y_pred = self.model.predict(np.asarray(X_test))
        pred_proba = self.model.predict_proba(np.asarray(X_test))
        pred_proba_percent = pred_proba[0] * 100

        results = []
        for label, conf in zip(y_pred, pred_proba_percent):
            if label == 0:
                result = {"Label": "Goodware", "Confidence level": float(conf)}
            else:
                result = {"Label": "Malware", "Confidence level": float(conf)}
            results.append(result)

        return results


# Define the Django view function
@csrf_exempt
@require_POST
@csrf_exempt
@require_POST
def mal_prediction(request):
    if request.method == 'POST':
        try:
            # Attempt to parse JSON data from the request body
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            return HttpResponse("Invalid JSON data", status=400)

        # Continue with further processing here

        predictor = MalwarePredictor(
            model_path="static/rf.pkl"
        )

        features = predictor.extract_features(data)
        result = predictor.predict(features)

        # Construct a JSON response
        response_data = {
            'message': 'Prediction result',
            'status': 'success',
            'result': result
        }

        json_response = JsonResponse(response_data, safe=False)

        return json_response

    # Handle other HTTP methods or return an error response for unsupported methods
    return HttpResponse("Method not allowed", status=405)




@csrf_exempt
def mTest1(request):
    data=np.array([["android/net/ConnectivityManager->getActiveNetworkInfo android/bluetooth/BluetoothAdapter->disable android/app/WallpaperManager->setStream android/net/wifi/WifiManager->getConnectionInfo android/os/Vibrator->vibrate java/lang/Runtime->exec android/telephony/TelephonyManager->listen android/os/PowerManager$WakeLock->acquire android/bluetooth/BluetoothAdapter->getState android/content/Context->sendBroadcast android/location/LocationManager->requestLocationUpdates org/apache/http/impl/client/DefaultHttpClient android/content/ContentResolver->query android/provider/Settings$System->putInt android/net/wifi/WifiManager->setWifiEnabled android/content/pm/PackageManager->setComponentEnabledSetting",            "com.android.vending.CHECK_LICENSE android.permission.KILL_BACKGROUND_PROCESSES android.permission.READ_SMS android.permission.CALL_PHONE android.permission.WAKE_LOCK android.permission.SET_WALLPAPER_HINTS android.permission.INTERNET android.permission.WRITE_SETTINGS android.permission.WRITE_CONTACTS android.permission.BLUETOOTH_ADMIN android.permission.CHANGE_WIFI_STATE android.permission.ACCESS_FINE_LOCATION android.permission.BLUETOOTH android.permission.SET_WALLPAPER android.permission.WRITE_EXTERNAL_STORAGE android.permission.ACCESS_NETWORK_STATE android.permission.READ_CALENDAR android.permission.DIAL android.permission.READ_PHONE_STATE android.permission.READ_CONTACTS android.permission.ACCESS_WIFI_STATE android.permission.ACCESS_COARSE_LOCATION com.android.browser.permission.READ_HISTORY_BOOKMARKS android.permission.VIBRATE android.permission.PERSISTENT_ACTIVITY android.permission.RESTART_PACKAGES",
            "spbtraveler2.com spbtraveler1.com spbtraveler.com spb.com softspb.com spbtraveler3.com spb.com spbtraveler3.com spbtraveler.com spbtraveler2.com softspb.com spbtraveler.com spbtraveler3.com spbtraveler2.com spbtraveler1.com spbtraveler1.com",
            "com.softspb.weather.provider.WeatherProvider",
            "android.hardware.location android.hardware.bluetooth android.hardware.location.gps android.hardware.location.network android.hardware.screen.portrait android.hardware.touchscreen android.hardware.telephony android.hardware.wifi",
            "android.intent.category.HOME android.intent.action.MEDIA_MOUNTED android.intent.action.MEDIA_UNMOUNTED android.intent.category.DEFAULT android.intent.action.BOOT_COMPLETED android.intent.action.MAIN, activity: com.softspb.shell.LicenseActivity com.softspb.shell.restart com.softspb.weather",
            "getDeviceId getPackageInfo getSystemService Cipher(AES/CBC/PKCS5Padding) Read/Write External Storage getWifiState setWifiEnabled Execution of external commands printStackTrace Obfuscation(Base64)",
            "com.softspb.shell.adapters.imageviewer.ImageViewerService com.softspb.shell.service.ForegroundService com.softspb.weather.updateservice.spb.SPBForecastUpdateService com.softspb.shell.service.LicenseService com.softspb.weather.updateservice.spb.SPBCurrentUpdateService com.softspb.shell.SDCardReceiver com.softspb.weather.service.CurrentLocationService",
            "com.softspb.shell.LicenseActivity com.softspb.shell.restart com.softspb.weather",
            "android.permission.ACCESS_FINE_LOCATION android.permission.READ_LOGS android.permission.READ_CONTACTS android.permission.BLUETOOTH android.permission.READ_PHONE_STATE android.permission.WRITE_EXTERNAL_STORAGE android.permission.INTERNET android.permission.CALL_PHONE android.permission.ACCESS_COARSE_LOCATION android.permission.ACCESS_WIFI_STATE android.permission.RECEIVE_BOOT_COMPLETED android.permission.WRITE_CONTACTS",
            ]])
    predictor = MalwarePredictor(
            model_path="static/rf.pkl")

    features = predictor.extractFeaturesTest(data)
    result = predictor.predict(features)
    return JsonResponse(result, safe=False)


@csrf_exempt
@require_POST
def mTest2(request):
    result = {}
    if request.method == 'POST':
        result={}
        try:
            raw_json_data = request.body.decode('utf-8')
            data = json.loads(raw_json_data)
        except json.JSONDecodeError as e:
            return HttpResponse("Invalid JSON data",status=400)

        predictor = MalwarePredictor(
                model_path="static/rf.pkl")
        # values_list = list(data.values())

        # # Convert the list into a numpy array
        # data_np_array = np.array([values_list])

        # # Print the numpy array
        # print(data_np_array)
        features = predictor.extract_features(data)
        result = predictor.predict(features)
        return JsonResponse(result, safe=False)
   
