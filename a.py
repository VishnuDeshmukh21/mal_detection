'''
from django.http import HttpResponse

def home(request):
    return HttpResponse("Hello, Django!")
'''
import pandas as pd
import numpy as np
import pickle
import json
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer
@csrf_exempt
def mal_prediction(request):
    result = {}

    if request.method == 'POST':
        string_to_append = request.POST.get('stringToAppend')
        print("string_to_append:", string_to_append)
        try:
            data = json.loads(string_to_append)
            # print("Parsed data:", data)
        except json.JSONDecodeError as e:
            print("Error parsing JSON:",e)
            return HttpResponse("Invalid JSON data",status=400)
        print("**************")

        def extract_features(data):
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
                    print(f"Value for '{i}' is empty or None.")
                    raise ValueError(f"Missing feature: '{i}' is not present in the data.")

            ext_data = pd.DataFrame(static_features, index=[0])
            print(ext_data.shape)
            extracted_data = []
            for i in range(ext_data.shape[1]):
                print("Embedding column {}...".format(i))
                test_data = ext_data.values[:, i]
                # print(test_data.shape)
                tfidf = pickle.load(open("C:/Users/91701/Desktop/tej_sujan/malware/backend/tfidf_col{}.pkl".format(i), "rb"))
                test_tfidf = tfidf.transform(test_data).todense()

                if len(extracted_data) == 0:
                    extracted_data = test_tfidf
                else:
                    extracted_data = np.concatenate((extracted_data, test_tfidf), axis=1)

            return extracted_data

        X1_test = extract_features(data)


        def predict(normalized_features):
            # initialize classifier
            clf = pickle.load(open("C:/Users/91701/Desktop/tej_sujan/malware/backend/rf.pkl", "rb"))
            # predict test data
            y_pred = clf.predict(np.asarray(normalized_features))
            # get probabilities
            pred_proba = clf.predict_proba(np.asarray(normalized_features))
            print(pred_proba)
            # roundoff the confidence level
            pred_proba_percent1 = np.around(pred_proba[0] * 100,decimals=2)

            i = 0
            for label, conf in zip(y_pred,pred_proba_percent1):
                if label == 0:
                    d1 = {"Label": "Goodware","Confidence level":float(conf)}
                else:
                    d1 = {"Label": "Malware","Confidence level":float(conf)}
                i += 1
            return d1

        result = predict(X1_test)
        print(result)
    return JsonResponse(result,safe=True)
   
    

def mal1(request):
    print(request)
    try:
        X_dataTest = np.array([["android/net/ConnectivityManager->getActiveNetworkInfo android/bluetooth/BluetoothAdapter->disable android/app/WallpaperManager->setStream android/net/wifi/WifiManager->getConnectionInfo android/os/Vibrator->vibrate java/lang/Runtime->exec android/telephony/TelephonyManager->listen android/os/PowerManager$WakeLock->acquire android/bluetooth/BluetoothAdapter->getState android/content/Context->sendBroadcast android/location/LocationManager->requestLocationUpdates org/apache/http/impl/client/DefaultHttpClient android/content/ContentResolver->query android/provider/Settings$System->putInt android/net/wifi/WifiManager->setWifiEnabled android/content/pm/PackageManager->setComponentEnabledSetting",
            "com.android.vending.CHECK_LICENSE android.permission.KILL_BACKGROUND_PROCESSES android.permission.READ_SMS android.permission.CALL_PHONE android.permission.WAKE_LOCK android.permission.SET_WALLPAPER_HINTS android.permission.INTERNET android.permission.WRITE_SETTINGS android.permission.WRITE_CONTACTS android.permission.BLUETOOTH_ADMIN android.permission.CHANGE_WIFI_STATE android.permission.ACCESS_FINE_LOCATION android.permission.BLUETOOTH android.permission.SET_WALLPAPER android.permission.WRITE_EXTERNAL_STORAGE android.permission.ACCESS_NETWORK_STATE android.permission.READ_CALENDAR android.permission.DIAL android.permission.READ_PHONE_STATE android.permission.READ_CONTACTS android.permission.ACCESS_WIFI_STATE android.permission.ACCESS_COARSE_LOCATION com.android.browser.permission.READ_HISTORY_BOOKMARKS android.permission.VIBRATE android.permission.PERSISTENT_ACTIVITY android.permission.RESTART_PACKAGES",
            "spbtraveler2.com spbtraveler1.com spbtraveler.com spb.com softspb.com spbtraveler3.com spb.com spbtraveler3.com spbtraveler.com spbtraveler2.com softspb.com spbtraveler.com spbtraveler3.com spbtraveler2.com spbtraveler1.com spbtraveler1.com",
            "com.softspb.weather.provider.WeatherProvider",
            "android.hardware.location android.hardware.bluetooth android.hardware.location.gps android.hardware.location.network android.hardware.screen.portrait android.hardware.touchscreen android.hardware.telephony android.hardware.wifi",
            "android.intent.category.HOME android.intent.action.MEDIA_MOUNTED android.intent.action.MEDIA_UNMOUNTED android.intent.category.DEFAULT android.intent.action.BOOT_COMPLETED android.intent.action.MAIN, activity: com.softspb.shell.LicenseActivity com.softspb.shell.restart com.softspb.weather",
            "getDeviceId getPackageInfo getSystemService Cipher(AES/CBC/PKCS5Padding) Read/Write External Storage getWifiState setWifiEnabled Execution of external commands printStackTrace Obfuscation(Base64)",
            "com.softspb.shell.adapters.imageviewer.ImageViewerService com.softspb.shell.service.ForegroundService com.softspb.weather.updateservice.spb.SPBForecastUpdateService com.softspb.shell.service.LicenseService com.softspb.weather.updateservice.spb.SPBCurrentUpdateService com.softspb.shell.SDCardReceiver com.softspb.weather.service.CurrentLocationService",
            "com.softspb.shell.LicenseActivity com.softspb.shell.restart com.softspb.weather",
            "android.permission.ACCESS_FINE_LOCATION android.permission.READ_LOGS android.permission.READ_CONTACTS android.permission.BLUETOOTH android.permission.READ_PHONE_STATE android.permission.WRITE_EXTERNAL_STORAGE android.permission.INTERNET android.permission.CALL_PHONE android.permission.ACCESS_COARSE_LOCATION android.permission.ACCESS_WIFI_STATE android.permission.RECEIVE_BOOT_COMPLETED android.permission.WRITE_CONTACTS",
            ]])
        



        def feature_extraction(X_dataTest):
            X_test = []
            models=[]
            # iterate over each column
            for i in range(X_dataTest.shape[1]):
                print("Embeddding column {}...".format(i))

                test_data = X_dataTest[:,i]
                print(test_data.shape)
                tfidf = pickle.load(open("C:/Users/K TEJASWI/Documents/projects/duplicate_server/web_project/hello/tfidf_col{}.pkl".format(i), "rb"))

                test_tfidf = tfidf.transform(test_data).todense()
                print(test_tfidf.shape)

                # if first execution, save only features
                if len(X_test) == 0:
                    X_test = test_tfidf
                # concatenate existing features
                else:
                    print(X_test.shape)
                    X_test = np.concatenate((X_test,test_tfidf),axis=1)
                    print(X_test.shape)
                    models.append(tfidf)

            return(X_test)
        X1_test = feature_extraction(X_dataTest)
        print(X1_test)

        def predict(X_test):
            clf = pickle.load(open("C:/Users/K TEJASWI/Documents/projects/duplicate_server/web_project/hello/rf.pkl","rb"))
            # predict test data
            y_pred = clf.predict(np.asarray(X_test))
            # get probabilities
            pred_proba = clf.predict_proba(np.asarray(X_test))
            pred_proba_percent=pred_proba[0]*100
            # get probabilities
            i = 0

            for label, conf in zip(y_pred,pred_proba_percent):
                if label == 0:
                    d1={ "Label":"Goodware","Confidence level" :conf}
                else:
                    d1={ "Label ":"Malware","Confidence level" :conf}
                i += 1
            return d1


        # Format predictions and confidence level into a response
        p=predict(X1_test)
        print(p)
        # Return the response as JSON
        return JsonResponse(p,safe=True)

    except Exception as e:
        # Handle exceptions here
        print("Error occurred:", str(e))
        # You can log the error or return a custom error response
        return JsonResponse({"Error": "An error occurred while processing the request."}, status=500)
  


def andmal(request):
    print(request)
    loaded=pickle.load(open("C:/Users/K TEJASWI/Documents/projects/duplicate_server/web_project/hello/pickle_ooo.pkl","rb"))
    sample=np.array([8.41582295e-01, 4.32045935e-02, 1.00000000e+00 ,3.56841717e-02,
                     4.12296752e-04, 9.85618351e-03, 1.60672688e-01, 1.60672688e-01,
                     1.60672688e-01, 0.00000000e+00, 0.00000000e+00, 2.64378168e-05,
                     1.89661305e-06, 1.21874139e-02, 1.60880962e-05, 0.00000000e+00,
                     0.00000000e+00, 0.00000000e+00, 0.00000000e+00 ,0.00000000e+00,
                     0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
                     1.95688098e-01, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
                     0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
                     0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
                     0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 1.86678120e-02,
                     6.52076697e-01, 0.00000000e+00, 0.00000000e+00 ,0.00000000e+00,
                     0.00000000e+00])

    sample_reshaped = np.reshape(sample,(1,-1))
    model_l=loaded.predict(sample_reshaped)
    pred_prob = loaded.predict_proba([sample])
    confidence_levels=pred_prob[0]*100

    i=0
    for label, conf in zip(model_l,confidence_levels):
                if label == 0:
                    d1={ "Label":"Goodware","Confidence level" :conf}
                else:
                    d1={ "Label ":"Malware","Confidence level" :conf}
                i += 1
    print(d1)
    return JsonResponse(d1,safe=False)
 

