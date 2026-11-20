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
const sessionPanel = document.querySelector("#session-panel");
const sessionCopy = document.querySelector("#session-copy");
const signoutButton = document.querySelector("#signout-button");
const mainWebsiteUrl = "https://smwendwajaku5.github.io/anime_website/";

let isSignUp = true;

const googleMessages = {
    signed_in: "Signed in with Google.",
    not_configured: "Google sign-in is not configured. Add your Google OAuth credentials to .env.",
    invalid_state: "Google sign-in expired or could not be verified. Please try again.",
    cancelled: "Google sign-in was cancelled.",
    account_exists: "An account with this email already exists. Sign in with it first, then choose Continue with Google to link it.",
    provider_error: "Google sign-in could not be completed. Please try again."
};

const pageUrl = new URL(window.location.href);
const googleResult = pageUrl.searchParams.get("google");
if (googleResult) {
    formStatus.textContent = googleMessages[googleResult] || googleMessages.provider_error;
    pageUrl.searchParams.delete("google");
    history.replaceState(null, "", `${pageUrl.pathname}${pageUrl.search}${pageUrl.hash}`);
}

async function refreshSession() {
    try {
        const response = await fetch("/api/auth/session");
        if (!response.ok) {
            throw new Error("Session check failed.");
        }
        const result = await response.json();
        sessionPanel.hidden = !result.authenticated;
        if (result.authenticated) {
            sessionCopy.textContent = `Signed in as ${result.username}.`;
        }
    } catch (error) {
        console.error("Could not check sign-in session:", error);
        formStatus.textContent = "Could not check your sign-in session. Please refresh the page.";
    }
}

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

signoutButton.addEventListener("click", async () => {
    signoutButton.disabled = true;
    try {
        const response = await fetch("/api/auth/signout", { method: "POST" });
        if (!response.ok) {
            throw new Error("Sign-out request failed.");
        }
        sessionPanel.hidden = true;
        formStatus.textContent = "Signed out.";
    } catch (error) {
        console.error("Sign-out request failed:", error);
        formStatus.textContent = "Could not sign out. Please try again.";
    } finally {
        signoutButton.disabled = false;
    }
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
        if (response.ok && !isSignUp) {
            window.location.assign(mainWebsiteUrl);
        }
    } catch (error) {
        console.error("Authentication request failed:", error);
        formStatus.textContent = "Could not reach the server. Start the app with npm start and open http://127.0.0.1:3000.";
    } finally {
        submitButton.disabled = false;
    }
});

refreshSession();