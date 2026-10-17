
from django.shortcuts import render, redirect
from django.contrib.auth import (
    login as auth_login,
    logout as auth_logout,
    authenticate,
    get_user_model,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_POST

from urllib.parse import urlparse
from .models import EmailAnalysis

import re
import ipaddress


User = get_user_model()


# ==================================================
# REGISTRATION
# Username + Email Address + Password
# ==================================================

def register_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = UserCreationForm(request.POST)
        email = request.POST.get("email", "").strip()

        if form.is_valid():
            # Validate the email address.
            try:
                validate_email(email)
            except ValidationError:
                messages.error(
                    request,
                    "Please enter a valid email address."
                )
                return render(
                    request,
                    "detector/register.html",
                    {"form": form}
                )

            # Email addresses must be unique.
            if User.objects.filter(email__iexact=email).exists():
                messages.error(
                    request,
                    "This email address is already registered. "
                    "Please use another email address."
                )
                return render(
                    request,
                    "detector/register.html",
                    {"form": form}
                )

            # Save the username and password.
            user = form.save()

            # Save the email address to the user account.
            user.email = email
            user.save(update_fields=["email"])

            messages.success(
                request,
                "Registration successful! Please log in "
                "using your email address and password."
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
# LOGIN USING EMAIL ADDRESS AND PASSWORD
# ==================================================

def login_view(request):
    if request.user.is_authenticated:
        return redirect("home")

    form = AuthenticationForm(request)

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")

        if not email or not password:
            messages.error(
                request,
                "Please enter your email address and password."
            )

        else:
            try:
                validate_email(email)

            except ValidationError:
                messages.error(
                    request,
                    "Please enter a valid email address."
                )

            else:
                # Find the account using the registered email.
                user_record = User.objects.filter(
                    email__iexact=email
                ).first()

                if user_record is not None:
                    # Django's default authentication backend
                    # authenticates using the username.
                    user = authenticate(
                        request,
                        username=user_record.get_username(),
                        password=password,
                    )
                else:
                    user = None

                if user is not None:
                    auth_login(request, user)

                    messages.success(
                        request,
                        "Login successful! Welcome to BankGuard."
                    )

                    return redirect("home")

                messages.error(
                    request,
                    "Invalid email address or password."
                )

    return render(
        request,
        "detector/login.html",
        {"form": form}
    )


# ==================================================
# LOGOUT
# ==================================================

@login_required
@require_POST
def logout_view(request):
    auth_logout(request)

    messages.success(
        request,
        "You have logged out successfully."
    )

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
    """Return True if the hostname is an IP address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True

    except ValueError:
        return False


# ==================================================
# HELPER: PHISHING EMAIL ANALYSIS
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

    # --------------------------------------------------
    # 1. PHISHING KEYWORDS
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 2. SENSITIVE INFORMATION
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 3. URGENCY AND THREATS
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 4. CLICK AND VERIFICATION REQUESTS
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 5. BANK ACCOUNT REFERENCES
    # --------------------------------------------------

    if "bank" in tokens and "account" in tokens:
        add_reason(
            5,
            "Email refers to a bank account."
        )

    # --------------------------------------------------
    # 6. SUSPICIOUS OFFERS
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 7. URL ANALYSIS
    # --------------------------------------------------

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
        hostname = (parsed_url.hostname or "").lower().rstrip(".")

        # HTTP instead of HTTPS.
        if parsed_url.scheme.lower() == "http":
            add_reason(
                5,
                "Email contains an HTTP URL instead of HTTPS."
            )

        # IP address used instead of a domain name.
        if is_ip_address(hostname):
            add_reason(
                15,
                "URL uses an IP address instead of a normal domain name."
            )

        # @ symbol may obscure the destination.
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

        # Suspicious domain extension.
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

    # --------------------------------------------------
    # 8. BANK AND DOMAIN MISMATCH
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 9. FINAL SCORE AND RISK CLASSIFICATION
    # --------------------------------------------------

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

        analysis = analyze_email(original_email)

        EmailAnalysis.objects.create(
            user=request.user,
            email_text=original_email,
            risk_score=analysis["score"],
            risk_level=analysis["risk_level"],
            reasons="\n".join(analysis["reasons"]),
            recommendation=analysis["recommendation"],
        )

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
