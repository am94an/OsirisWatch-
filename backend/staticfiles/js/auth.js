document.addEventListener("DOMContentLoaded", () => {
    // Toggle between login and signup forms
    const showSignup = document.getElementById("showSignup");
    const showLogin = document.getElementById("showLogin");
    const loginBox = document.getElementById("loginBox");
    const signupBox = document.getElementById("signupBox");

    showSignup.addEventListener("click", (e) => {
        e.preventDefault();
        loginBox.style.display = "none";
        signupBox.style.display = "block";
    });

    showLogin.addEventListener("click", (e) => {
        e.preventDefault();
        signupBox.style.display = "none";
        loginBox.style.display = "block";
    });
});

document.addEventListener("DOMContentLoaded", () => {
    // Fade-out animation for forms
    const forms = document.querySelectorAll("form");
    const loginBoxes = document.querySelectorAll(".login-box");

    loginBoxes.forEach(box => {
        box.classList.add("show"); 
    });

    forms.forEach(form => {
        form.addEventListener("submit", function(event) {
            form.classList.add("fade-out");
        });
    });
});
