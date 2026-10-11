
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages

from urllib.parse import urlparse
from .models import EmailAnalysis

import re
import ipaddress


# ==================================================
# REGISTRATION
# ==================================================

def register_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = UserCreationForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(
                request,
                "Registration successful! Please log in."
            )
            return redirect("login")

        messages.error(
            request,
            "Please correct the errors in the registration form."
        )
    else:
        form = UserCreationForm()

    return render(
        request,
        "detector/register.html",
        {"form": form}
    )


# ==================================================
# LOGIN
# ==================================================

def login_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = AuthenticationForm(
            request,
            data=request.POST
        )

        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)

            messages.success(
                request,
                "Login successful!"
            )
            return redirect("home")

        messages.error(
            request,
            "Invalid username or password."
        )
    else:
        form = AuthenticationForm(request)

    return render(
        request,
        "detector/login.html",
        {"form": form}
    )


# ==================================================
# LOGOUT
# ==================================================

def logout_view(request):
    if request.method == "POST":
        auth_logout(request)

        messages.success(
            request,
            "You have logged out successfully."
        )

        return redirect("login")

    # Logout should be submitted using POST.
    return redirect("login")


# ==================================================
# HELPER: URL EXTRACTION
# ==================================================

def extract_urls(text):
    """Extract HTTP and HTTPS URLs from submitted email text."""

    found_urls = re.findall(
        r"""https?://[^\s<>"']+""",
        text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in found_urls:
        url = url.rstrip(".,!?;:)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# ==================================================
# HELPER: IP ADDRESS CHECK
# ==================================================

def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


# ==================================================
# HELPER: PHISHING ANALYSIS
# ==================================================

def analyze_email(email_text):
    text = email_text.lower()

    tokens = set(
        re.findall(r"\b[a-z0-9]+\b", text)
    )

    score = 0
    reasons = []
    detected_keywords = []

    def add_reason(points, message):
        nonlocal score
        score += points

        if message not in reasons:
            reasons.append(message)

    # ----------------------------------------------
    # PHISHING KEYWORDS
    # ----------------------------------------------

    phishing_keywords = [
        "urgent",
        "verify",
        "password",
        "otp",
        "pin",
        "cvv",
        "click here",
        "bank account",
        "account blocked",
        "account suspended",
        "free money",
        "won prize",
    ]

    for keyword in phishing_keywords:
        if " " in keyword:
            matched = keyword in text
        else:
            matched = keyword in tokens

        if matched:
            score += 5
            detected_keywords.append(keyword)

    # ----------------------------------------------
    # SENSITIVE INFORMATION REQUESTS
    # ----------------------------------------------

    if "otp" in tokens:
        add_reason(
            15,
            "Email requests or mentions an OTP."
        )

    if "password" in tokens:
        add_reason(
            15,
            "Email requests or mentions a password."
        )

    if "pin" in tokens:
        add_reason(
            10,
            "Email requests or mentions a PIN."
        )

    if "cvv" in tokens:
        add_reason(
            10,
            "Email requests or mentions CVV information."
        )

    # ----------------------------------------------
    # URGENCY / THREATS
    # ----------------------------------------------

    urgent_phrases = [
        "urgent",
        "immediately",
        "within 24 hours",
        "account will be blocked",
        "account suspended",
        "immediate action",
    ]

    if any(phrase in text for phrase in urgent_phrases):
        add_reason(
            15,
            "Email uses urgent or threatening language."
        )

    # ----------------------------------------------
    # CLICK / VERIFICATION
    # ----------------------------------------------

    if "click" in tokens and "here" in tokens:
        add_reason(
            10,
            "Email asks the user to click a link."
        )

    if "verify" in tokens:
        add_reason(
            10,
            "Email asks the user to verify an account or information."
        )

    # ----------------------------------------------
    # BANK ACCOUNT REFERENCES
    # ----------------------------------------------

    if "bank" in tokens and "account" in tokens:
        add_reason(
            5,
            "Email refers to a bank account."
        )

    # ----------------------------------------------
    # SUSPICIOUS OFFERS
    # ----------------------------------------------

    if "free" in tokens and "money" in tokens:
        add_reason(
            10,
            "Email contains a suspicious money-related offer."
        )

    if "won" in tokens and "prize" in tokens:
        add_reason(
            10,
            "Email contains suspicious prize or reward language."
        )

    # ----------------------------------------------
    # URL ANALYSIS
    # ----------------------------------------------

    urls = extract_urls(email_text)

    suspicious_extensions = (
        ".xyz",
        ".top",
        ".click",
        ".live",
        ".site",
        ".online",
        ".win",
    )

    suspicious_domain_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "validation",
        "security",
    ]

    for url in urls:
        parsed_url = urlparse(url)

        hostname = (
            parsed_url.hostname or ""
        ).lower()

        # HTTP instead of HTTPS.
        if parsed_url.scheme.lower() == "http":
            add_reason(
                5,
                "Email contains an HTTP URL instead of HTTPS."
            )

        # IP address used as the URL hostname.
        if is_ip_address(hostname):
            add_reason(
                15,
                "URL uses an IP address instead of a normal domain name."
            )

        # @ symbol in the URL.
        if "@" in url:
            add_reason(
                15,
                "URL contains an @ symbol that may obscure its destination."
            )

        # Unusually long URL.
        if len(url) > 100:
            add_reason(
                10,
                "URL is unusually long and may contain suspicious parameters."
            )

        # Potentially suspicious domain extension.
        if any(
            hostname.endswith(extension)
            for extension in suspicious_extensions
        ):
            add_reason(
                10,
                "URL uses a potentially suspicious domain extension."
            )

        # Suspicious words in the hostname.
        if any(
            word in hostname
            for word in suspicious_domain_words
        ):
            add_reason(
                5,
                "URL domain contains banking or verification-related words."
            )

    if urls:
        add_reason(
            5,
            "Email contains a URL that should be checked carefully."
        )

    # ----------------------------------------------
    # BANK / DOMAIN MISMATCH
    # ----------------------------------------------

    banks = {
        "sbi": "sbi.co.in",
        "hdfc": "hdfcbank.com",
        "icici": "icicibank.com",
        "axis": "axisbank.com",
        "canara": "canarabank.com",
    }

    detected_bank = None

    for bank_name in banks:
        if re.search(
            r"\b" + re.escape(bank_name) + r"\b",
            text
        ):
            detected_bank = bank_name
            break

    if detected_bank and urls:
        official_domain = banks[detected_bank]
        mismatch_found = False

        for url in urls:
            hostname = (
                urlparse(url).hostname or ""
            ).lower().rstrip(".")

            if not (
                hostname == official_domain
                or hostname.endswith("." + official_domain)
            ):
                mismatch_found = True
                break

        if mismatch_found:
            add_reason(
                20,
                (
                    f"Email mentions {detected_bank.upper()}, "
                    "but the URL does not match the expected bank domain."
                )
            )

    # ----------------------------------------------
    # SCORE AND RISK CLASSIFICATION
    # ----------------------------------------------

    score = min(score, 100)

    if score >= 71:
        risk_level = "HIGH"
        result = "Phishing Email Detected"

        recommendation = (
            "Do not click links or share OTP, PIN, CVV, "
            "or passwords. Verify the message through the "
            "bank's official website or phone number."
        )

    elif score >= 31:
        risk_level = "MEDIUM"
        result = "Suspicious Email"

        recommendation = (
            "Be careful with this email. Verify the sender "
            "and website independently before taking action. "
            "Do not share confidential banking information."
        )

    else:
        risk_level = "LOW"
        result = "Low Risk Email"

        recommendation = (
            "The email has fewer suspicious indicators under "
            "the current rules. This does not guarantee that "
            "the email is genuine. Verify the sender and links."
        )

    if not reasons:
        reasons.append(
            "No configured phishing indicators were detected."
        )

    return {
        "result": result,
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "detected_keywords": detected_keywords,
        "recommendation": recommendation,
    }


# ==================================================
# HOME / EMAIL PHISHING DETECTOR
# ==================================================

@login_required
def home(request):
    context = {
        "result": "",
        "score": 0,
        "risk_level": "",
        "reasons": [],
        "detected_keywords": [],
        "recommendation": "",
    }

    # Display the most recent result after redirect.
    saved_result = request.session.pop(
        "latest_analysis_result",
        None
    )

    if saved_result:
        context.update(saved_result)

    if request.method == "POST":
        original_email = request.POST.get(
            "email",
            ""
        ).strip()

        if not original_email:
            messages.error(
                request,
                "Please enter an email to analyze."
            )

            return render(
                request,
                "detector/home.html",
                context
            )

        # Analyze the submitted email.
        analysis = analyze_email(original_email)

        # Save the analysis for the logged-in user.
        EmailAnalysis.objects.create(
            user=request.user,
            email_text=original_email,
            risk_score=analysis["score"],
            risk_level=analysis["risk_level"],
            reasons="\n".join(analysis["reasons"]),
            recommendation=analysis["recommendation"],
        )

        # Store the result temporarily for the redirected GET.
        request.session["latest_analysis_result"] = {
            **analysis,
            "email": original_email,
        }

        messages.success(
            request,
            "Email analysis completed and saved to your history."
        )

        return redirect("home")

    return render(
        request,
        "detector/home.html",
        context
    )


# ==================================================
# USER-SPECIFIC ANALYSIS HISTORY
# ==================================================

@login_required
def history(request):
    analyses = EmailAnalysis.objects.filter(
        user=request.user
    ).order_by(
        "-analyzed_at",
        "-id"
    )

    return render(
        request,
        "detector/history.html",
        {
            "analyses": analyses,
            "total_records": analyses.count(),
        }
    )


# ==================================================
# USER-SPECIFIC DASHBOARD
# ==================================================

@login_required
def dashboard(request):
    user_analyses = EmailAnalysis.objects.filter(
        user=request.user
    )

    context = {
        "total": user_analyses.count(),

        "phishing": user_analyses.filter(
            risk_level="HIGH"
        ).count(),

        "suspicious": user_analyses.filter(
            risk_level="MEDIUM"
        ).count(),

        "safe": user_analyses.filter(
            risk_level="LOW"
        ).count(),
    }

    return render(
        request,
        "detector/dashboard.html",
        context
    )
