package com.example.phishguard

import android.app.DatePickerDialog
import android.content.Intent
import android.os.Bundle
import android.util.Patterns
import android.widget.*
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.gms.auth.api.signin.*
import com.google.android.gms.common.api.ApiException
import com.google.android.material.button.MaterialButton
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.firestore.FieldValue
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.SetOptions
import java.util.*

class SignupActivity : AppCompatActivity() {

    private lateinit var auth: FirebaseAuth
    private lateinit var db: FirebaseFirestore
    private lateinit var googleSignInClient: GoogleSignInClient
    private lateinit var googleSignInLauncher: ActivityResultLauncher<Intent>

    private val countries = Locale.getISOCountries().map {
        Locale("", it).displayCountry
    }.sorted().toTypedArray()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_signup)

        auth = FirebaseAuth.getInstance()
        db = FirebaseFirestore.getInstance()

        setupGoogleSignIn()
        setupGoogleSignInLauncher()
        setupDobPicker()
        setupCountryDropdown()

        findViewById<MaterialButton>(R.id.btnSignup).setOnClickListener {
            signupWithEmail()
        }

        findViewById<MaterialButton>(R.id.btnGoogleSignup).setOnClickListener {

            googleSignInClient.signOut().addOnCompleteListener {
                googleSignInLauncher.launch(googleSignInClient.signInIntent)
            }

        }

        findViewById<TextView>(R.id.tvLogin).setOnClickListener {

            startActivity(Intent(this, LoginActivity::class.java))
            finish()

        }
    }


    private fun setupCountryDropdown() {

        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_dropdown_item_1line,
            countries
        )

        val etCountry = findViewById<AutoCompleteTextView>(R.id.etCountry)

        etCountry.setAdapter(adapter)
        etCountry.threshold = 1
    }

    private fun setupDobPicker() {

        val etDob = findViewById<EditText>(R.id.etDob)

        etDob.setOnClickListener { showDatePicker(etDob) }

        etDob.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) showDatePicker(etDob)
        }
    }

    private fun showDatePicker(etDob: EditText) {

        val cal = Calendar.getInstance()

        DatePickerDialog(
            this,
            { _, year, month, day ->

                etDob.setText(
                    "%02d/%02d/%04d".format(
                        day,
                        month + 1,
                        year
                    )
                )

            },
            cal.get(Calendar.YEAR),
            cal.get(Calendar.MONTH),
            cal.get(Calendar.DAY_OF_MONTH)

        ).apply {

            datePicker.maxDate = System.currentTimeMillis()
            show()

        }
    }

    private fun setupGoogleSignIn() {

        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestIdToken(getString(R.string.default_web_client_id))
            .build()

        googleSignInClient = GoogleSignIn.getClient(this, gso)
    }

    private fun setupGoogleSignInLauncher() {

        googleSignInLauncher =
            registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->

                if (result.resultCode != RESULT_OK) {
                    toast("Google sign-in cancelled")
                    return@registerForActivityResult
                }

                val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)

                try {

                    val account = task.getResult(ApiException::class.java)
                    firebaseAuthWithGoogle(account)

                } catch (e: ApiException) {

                    toast("Google sign-in failed")

                }
            }
    }


    private fun signupWithEmail() {

        val name = findViewById<EditText>(R.id.etName).text.toString().trim()
        val email = findViewById<EditText>(R.id.etEmail).text.toString().trim()
        val dob = findViewById<EditText>(R.id.etDob).text.toString().trim()
        val phone = findViewById<EditText>(R.id.etPhone).text.toString().trim()
        val country = findViewById<AutoCompleteTextView>(R.id.etCountry).text.toString().trim()
        val password = findViewById<EditText>(R.id.etPassword).text.toString()
        val confirmPassword = findViewById<EditText>(R.id.etConfirmPassword).text.toString()

        if (name.isEmpty() || email.isEmpty() || dob.isEmpty() ||
            phone.isEmpty() || country.isEmpty() ||
            password.isEmpty() || confirmPassword.isEmpty()
        ) {

            toast("All fields are required")
            return
        }

        if (!Patterns.EMAIL_ADDRESS.matcher(email).matches()) {

            toast("Invalid email address")
            return
        }

        if (password.length < 6) {

            toast("Password must be at least 6 characters")
            return
        }

        if (password != confirmPassword) {

            toast("Passwords do not match")
            return
        }

        auth.createUserWithEmailAndPassword(email, password)
            .addOnSuccessListener { result ->

                val uid = result.user?.uid ?: return@addOnSuccessListener
                saveUserData(uid, name, email, dob, phone, country)

            }
            .addOnFailureListener {

                toast(it.message ?: "Signup failed")

            }
    }


    private fun firebaseAuthWithGoogle(account: GoogleSignInAccount) {

        val credential = GoogleAuthProvider.getCredential(account.idToken, null)

        auth.signInWithCredential(credential)
            .addOnSuccessListener { result ->

                val user = result.user ?: return@addOnSuccessListener
                val uid = user.uid

                val userData = hashMapOf(

                    "name" to (user.displayName ?: ""),
                    "email" to (user.email ?: ""),
                    "authProvider" to "google",
                    "createdAt" to FieldValue.serverTimestamp()

                )

                db.collection("users")
                    .document(uid)
                    .set(userData, SetOptions.merge())
                    .addOnSuccessListener {

                        goToMain()

                    }
                    .addOnFailureListener {

                        goToMain()

                    }

            }
            .addOnFailureListener {

                toast("Google authentication failed")

            }
    }


    private fun saveUserData(
        uid: String,
        name: String,
        email: String,
        dob: String,
        phone: String,
        country: String
    ) {

        val userData = hashMapOf(

            "name" to name,
            "email" to email,
            "dob" to dob,
            "phone" to phone,
            "country" to country,
            "authProvider" to "email",
            "createdAt" to FieldValue.serverTimestamp()

        )

        db.collection("users")
            .document(uid)
            .set(userData)
            .addOnSuccessListener {

                toast("Account created successfully")
                goToMain()

            }
            .addOnFailureListener {

                toast("Failed to save user data")

            }
    }

    private fun goToMain() {

        startActivity(Intent(this, MainActivity::class.java))
        finish()

    }

    private fun toast(msg: String) {

        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    }
}