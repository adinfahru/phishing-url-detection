#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction
import joblib
from urllib.parse import urlparse

def is_phishing_gbc(x):
    #LOAD PICKLE
    file_gbc = r"model\gbc_model.pkl"
    gbc = joblib.load(file_gbc)

    # PREDIKSI GRADIENT BOOST
    gbc_prediction = gbc.predict(x)
    gbc_safe_probability = round(gbc.predict_proba(x)[0,1] * 100, 2)
    gbc_malicious_probability = round(gbc.predict_proba(x)[0,0] * 100, 2)

    y_test_gbc = gbc.predict(X_test)
    acc_test_gbc = accuracy_score(y_test,y_test_gbc) * 100

    return {
        "gbc_prediction": gbc_prediction,
        "gbc_safe_probability": gbc_safe_probability,
        "gbc_malicious_probability": gbc_malicious_probability,
        "gbc_acc_test": acc_test_gbc
    }

def is_phishing_cat(x):
    file_cat = r"model\cat_model.pkl"
    cat = joblib.load(file_cat)

    # PREDIKSI CATBOOST
    cat_prediction = cat.predict(x)
    cat_safe_probability = round(cat.predict_proba(x)[0,1] * 100, 2)
    cat_malicious_probability = round(cat.predict_proba(x)[0,0] * 100, 2)

    y_test_cat = cat.predict(X_test)
    acc_test_cat = accuracy_score(y_test,y_test_cat) * 100

    return {
        "cat_prediction": cat_prediction,
        "cat_safe_probability": cat_safe_probability,
        "cat_malicious_probability": cat_malicious_probability,
        "cat_acc_test": acc_test_cat
    }

def is_phishing_mlp(x):
    file_mlp = r"model\mlp_model.pkl"
    mlp = joblib.load(file_mlp)

    # PREDIKSI MULTI-LAYER
    mlp_prediction = mlp.predict(x)
    mlp_safe_probability = round(mlp.predict_proba(x)[0,1] * 100 ,2)
    mlp_malicious_probability = round(mlp.predict_proba(x)[0,0] * 100 , 2)

    y_test_mlp = mlp.predict(X_test)
    acc_test_mlp = accuracy_score(y_test,y_test_mlp) * 100

    return {
        "mlp_prediction": mlp_prediction,
        "mlp_safe_probability": mlp_safe_probability,
        "mlp_malicious_probability": mlp_malicious_probability,
        "mlp_acc_test": acc_test_mlp
    }

def Load_Data():
    global X_test, y_test

    X_test_file = r"model\X_test.pkl"
    X_test = joblib.load(X_test_file)

    y_test_file = r"model\y_test.pkl"
    y_test = joblib.load(y_test_file)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        Load_Data()

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        gbc_result = is_phishing_gbc(x)
        cat_result = is_phishing_cat(x)
        mlp_result = is_phishing_mlp(x)

        domain = urlparse(url).netloc
        issuer_valid, issued_by = FeatureExtraction.retSSLIssuer(domain)

        chart = True

        return render_template('index.html',**gbc_result, **cat_result,**mlp_result ,url=url, chart=chart,issuer_valid=issuer_valid ,issued_by=issued_by)
    else:
        gbc_result = {
            "gbc_prediction": -1,
            "gbc_safe_probability": -1,
            "gbc_malicious_probability": -1,
            "gbc_acc_test": -1
        }
        cat_result = {
            "cat_prediction": -1,
            "cat_safe_probability": -1,
            "cat_malicious_probability": -1,
            "cat_acc_test": -1
        }
        mlp_result = {
            "mlp_prediction": -1,
            "mlp_safe_probability": -1,
            "mlp_malicious_probability": -1,
            "mlp_acc_test": -1
        }
        
        chart = False
        return render_template("index.html", **gbc_result, **cat_result, **mlp_result, chart=chart, issuer_valid= -2, issued_by= -2)


if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0", port=5000)
