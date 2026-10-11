# BankGuard – Bank Email Phishing Detection System

## Project Overview

BankGuard is a web-based application developed using Python and Django to identify potential phishing emails related to banking. It analyzes email content using predefined rules and assigns a risk score to help users recognize suspicious emails.

## Objectives

- Detect suspicious bank-related emails.
- Identify phishing-related keywords such as OTP, PIN, CVV, and password.
- Analyze URLs for suspicious patterns.
- Calculate a risk score between 0 and 100.
- Classify emails into Low, Medium, and High risk levels.
- Display reasons for the detected risk.
- Maintain analysis history and display statistics through a dashboard.

## Technologies Used

- Frontend: HTML, CSS, Bootstrap
- Backend: Python, Django
- Database: SQLite
- Development Environment: Visual Studio Code

## Key Features

- User registration and login
- Bank email phishing analysis
- Risk score calculation
- Low, Medium, and High risk classification
- Suspicious indicator explanations
- Analysis history
- Dashboard with analysis statistics

## How It Works

1. The user enters bank-related email content.
2. The system checks for suspicious keywords and URL patterns.
3. A risk score is calculated using predefined rules.
4. The email is classified into Low, Medium, or High risk.
5. The result and recommended precautions are displayed.

## Future Enhancements

- Machine learning-based phishing detection
- Real-time URL reputation checking
- Email file upload support
- Improved detection of new phishing techniques

## Disclaimer

BankGuard is an educational project that uses rule-based analysis. Its results are not guaranteed to be accurate, and a Low Risk result does not necessarily mean an email is safe. Users should avoid sharing sensitive information through suspicious emails or links.

## Project Purpose

This project was developed as an academic mini-project to demonstrate web development and cybersecurity concepts in bank email phishing detection.