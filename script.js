const authForm = document.querySelector("#auth-form");
const modeToggle = document.querySelector("#mode-toggle");
const nameField = document.querySelector("#name-field");
const confirmField = document.querySelector("#confirm-field");
const passwordInput = document.querySelector("#password");
const confirmPasswordInput = document.querySelector("#confirm-password");
const formTitle = document.querySelector("#form-title");
const formSubtitle = document.querySelector("#form-subtitle");
const submitButton = document.querySelector("#submit-button");
const toggleCopy = document.querySelector("#toggle-copy");
const formStatus = document.querySelector("#form-status");

let isSignUp = true;

function validatePasswordMatch() {
    const passwordsMatch = passwordInput.value === confirmPasswordInput.value;
    confirmPasswordInput.setCustomValidity(
        isSignUp && confirmPasswordInput.value && !passwordsMatch
            ? "Passwords do not match."
            : ""
    );
}

passwordInput.addEventListener("input", validatePasswordMatch);
confirmPasswordInput.addEventListener("input", validatePasswordMatch);

modeToggle.addEventListener("click", () => {
    isSignUp = !isSignUp;

    nameField.hidden = !isSignUp;
    confirmField.hidden = !isSignUp;
    nameField.querySelector("input").required = isSignUp;
    confirmPasswordInput.required = isSignUp;
    passwordInput.autocomplete = isSignUp ? "new-password" : "current-password";
    confirmPasswordInput.value = "";
    confirmPasswordInput.setCustomValidity("");

    formTitle.textContent = isSignUp ? "Create your account" : "Welcome back";
    formSubtitle.textContent = isSignUp
        ? "Join the adventure. Your journey starts here."
        : "Sign in and continue your journey.";
    submitButton.textContent = isSignUp ? "Create account" : "Sign in";
    toggleCopy.textContent = isSignUp ? "Already have an account?" : "New to the adventure?";
    modeToggle.textContent = isSignUp ? "Sign in" : "Create account";
    formStatus.textContent = "";
});

authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    submitButton.disabled = true;
    formStatus.textContent = isSignUp ? "Creating your account..." : "Signing in...";

    const formData = new FormData(authForm);
    const payload = {
        email: formData.get("email"),
        password: formData.get("password")
    };
    if (isSignUp) {
        payload.username = formData.get("username");
    }

    try {
        const response = await fetch(isSignUp ? "/api/auth/signup" : "/api/auth/signin", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        formStatus.textContent = response.ok
            ? result.message
            : result.error || "The request could not be completed.";
    } catch (error) {
        console.error("Authentication request failed:", error);
        formStatus.textContent = "Could not reach the server. Start the app with npm start and open http://127.0.0.1:3000.";
    } finally {
        submitButton.disabled = false;
    }
});