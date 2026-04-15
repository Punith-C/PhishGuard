# PhishGuard

PhishGuard is a real-time phishing detection system that combines an Android application, a Node.js-based admin panel, and a machine learning pipeline to detect and monitor phishing threats efficiently.

The system performs on-device detection using a lightweight model and provides centralized monitoring through a web dashboard.

---

Overview

PhishGuard is designed to detect phishing URLs directly on the user’s device using machine learning. The detection results are sent to a backend admin panel where user activity and threats are monitored.

---

Project Structure

PhishGuard

├── PhishGuard_Android_App -    Android application (Kotlin)

├── PhishGuard_Admin -           Machine learning training pipeline, Node.js backend and dashboard          

---

Android Application

The Android application provides real-time phishing detection using an on-device model.

Features

* Real-time URL scanning
* Instant phishing alerts
* Offline detection using TensorFlow Lite
* Fast and lightweight performance
* User-friendly interface

Technology Stack

* Kotlin
* Android
* TensorFlow Lite

How to Run

* Open the project in Android Studio
* Allow Gradle to sync
* Update the backend server URL
* Run on a device or emulator (API 21+)

---

Admin Panel

The admin panel is built using Node.js and provides a web-based dashboard for monitoring user activity and phishing detection results.

Features

* Monitor user activity and detection logs
* View phishing detection results
* Manage user-reported threats
* REST API for Android communication
* Browser-based dashboard

Technology Stack

* Node.js
* Express.js
* HTML and JavaScript

---

Running the Admin Panel

Clone the repository
git clone [https://github.com/Punith-C/PhishGuard.git](https://github.com/Punith-C/PhishGuard.git)
cd PhishGuard/PhishGuard_Admin

Install dependencies
npm install

Run the server
node server.js

Access dashboard
[http://localhost:5000](http://localhost:5000)

Note
Ensure serviceAccountKey.json is present if Firebase is used.

---

Machine Learning Training

The training pipeline is implemented in Python and is responsible for building the phishing detection model.

Features

* URL feature extraction (hostname-based features)
* Neural Network model using TensorFlow
* XGBoost model for high-performance prediction
* Ensemble model combining both approaches
* Threshold-based classification
* Conversion to TensorFlow Lite for mobile deployment

Training Files

* Train_PhishGuard.py
* Dataset files inside Train_Model

---

Dependencies for Training

pip install --upgrade pip
pip install numpy pandas scikit-learn tensorflow matplotlib seaborn joblib xgboost

---

How to Train the Model

Navigate to training folder

cd Train_Model

Run training script

python Train_PhishGuard.py

Output Files

* phishing_model.tflite
* scaler files
* threshold.txt
* trusted_roots.txt

These files must be copied into the Android app assets folder.

---

Full System Setup

1. Clone the repository
   git clone [https://github.com/Punith-C/PhishGuard.git](https://github.com/Punith-C/PhishGuard.git)

2. Start the admin panel
   cd PhishGuard_Admin
   npm install
   node server.js

3. Copy the server URL
   Example [http://192.168.x.x:5000](http://192.168.x.x:5000)

4. Update this URL in the Android application

5. Build and run the Android application

6. (Optional) Train model and replace TFLite file

The system will now be fully connected and operational.

---

Workflow

User opens the Android app
User logs in

User chooses mode
Manual mode or Automatic mode

Manual mode
User enters a URL
App analyzes the URL using the model
Result is shown as safe or phishing

Automatic mode
App runs in background using VPN service
Monitors network traffic
Checks domains from DNS requests
If phishing is detected
Connection is blocked
User gets an alert

Admin panel
Admin monitors users only
Admin can see user details and activity
Admin can manage user information

---

Author

Punith C
GitHub [https://github.com/punith-c](https://github.com/punith-c)
