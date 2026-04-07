package com.example.phishguard

import android.content.Intent
import android.os.Bundle
import android.util.Patterns
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.gms.auth.api.signin.*
import com.google.android.gms.common.api.ApiException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.GoogleAuthProvider

class LoginActivity : AppCompatActivity() {

    private lateinit var auth: FirebaseAuth
    private lateinit var googleClient: GoogleSignInClient

    private val googleLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->

            if (result.resultCode != RESULT_OK) {
                toast("Google sign in cancelled")
                return@registerForActivityResult
            }

            val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)

            try {
                val account = task.getResult(ApiException::class.java)
                firebaseAuthWithGoogle(account)

            } catch (e: Exception) {
                toast("Google login failed")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        auth = FirebaseAuth.getInstance()

        if (auth.currentUser != null) {
            goToMain()
            return
        }

        setContentView(R.layout.activity_login)

        setupGoogle()

        findViewById<Button>(R.id.btnLogin).setOnClickListener {
            loginWithEmail()
        }

        findViewById<Button>(R.id.btnGoogleLogin).setOnClickListener {

            googleClient.signOut().addOnCompleteListener {
                googleLauncher.launch(googleClient.signInIntent)
            }

        }

        findViewById<TextView>(R.id.tvSignup).setOnClickListener {
            startActivity(Intent(this, SignupActivity::class.java))
        }
    }

    private fun setupGoogle() {

        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestIdToken(getString(R.string.default_web_client_id))
            .build()

        googleClient = GoogleSignIn.getClient(this, gso)
    }

    private fun loginWithEmail() {

        val email = findViewById<EditText>(R.id.etEmail).text.toString().trim()
        val password = findViewById<EditText>(R.id.etPassword).text.toString()

        if (email.isEmpty() || password.isEmpty()) {
            toast("Email and password required")
            return
        }

        if (!Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            toast("Invalid email")
            return
        }

        auth.signInWithEmailAndPassword(email, password)
            .addOnSuccessListener { goToMain() }
            .addOnFailureListener { toast(it.message ?: "Login failed") }
    }

    private fun firebaseAuthWithGoogle(account: GoogleSignInAccount) {

        val credential = GoogleAuthProvider.getCredential(account.idToken, null)

        auth.signInWithCredential(credential)
            .addOnSuccessListener {

                goToMain()

            }
            .addOnFailureListener {

                toast("Google authentication failed")

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