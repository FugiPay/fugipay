import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from pymongo import MongoClient
from flask import Flask, request, jsonify
import os
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MongoDB connection
MONGO_URI = os.getenv('MONGODB_URI')
if not MONGO_URI:
    logger.error('[FraudDetection] MONGODB_URI not set in .env file')
    raise ValueError('MONGODB_URI environment variable is required')
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client['zangena']
    # Test connection
    client.admin.command('ping')
    logger.info('[FraudDetection] Connected to MongoDB')
except Exception as e:
    logger.error(f'[FraudDetection] MongoDB connection failed: {e}')
    raise

# Initialize Flask app
app = Flask(__name__)

def fetch_user_data(username):
    """Fetch user transactions, pending deposits/withdrawals, and analytics data."""
    try:
        user = db.users.find_one(
            {'username': username},
            {'transactions': 1, 'pendingDeposits': 1, 'pendingWithdrawals': 1, 'depositAttempts': 1, 'lastWithdrawAttempts': 1}
        )
        analytics = list(db.analytics.find(
            {'identifier': username},
            {'data': 1, 'timestamp': 1}
        ))
        if not user:
            logger.error(f'[FraudDetection] User not found: {username}')
            raise ValueError('User not found')
        return user, analytics
    except Exception as e:
        logger.error(f'[FraudDetection] Error fetching user data: {e}')
        raise

def prepare_features(user, analytics, amount, ip, userAgent):
    """Prepare features for fraud detection."""
    transactions = user.get('transactions', [])
    pending_deposits = user.get('pendingDeposits', [])
    pending_withdrawals = user.get('pendingWithdrawals', [])
    
    # Calculate features
    deposit_count_24h = len([
        d for d in pending_deposits
        if d.get('date', datetime.now()) > datetime.now() - timedelta(hours=24)
    ])
    withdrawal_count_24h = len([
        w for w in pending_withdrawals
        if w.get('date', datetime.now()) > datetime.now() - timedelta(hours=24)
    ])
    avg_deposit_amount = np.mean([d['amount'] for d in pending_deposits]) if pending_deposits else 0
    avg_transaction_amount = np.mean([t['amount'] for t in transactions]) if transactions else 0
    analytics_count = len(analytics)
    error_count = sum(a['data'].get('errorCount', 0) for a in analytics)
    deposit_attempts = user.get('depositAttempts', 0)
    withdraw_attempts = user.get('lastWithdrawAttempts', 0)
    
    # IP and userAgent analysis (basic entropy check for anomalies)
    ip_entropy = len(set(ip.replace('.', ''))) if ip else 0
    ua_entropy = len(set(userAgent)) if userAgent else 0
    
    # Current transaction features
    amount_deviation = abs(amount - avg_deposit_amount) / (avg_deposit_amount + 1e-6)
    
    return np.array([[
        deposit_count_24h,
        withdrawal_count_24h,
        avg_deposit_amount,
        avg_transaction_amount,
        analytics_count,
        error_count,
        deposit_attempts,
        withdraw_attempts,
        ip_entropy,
        ua_entropy,
        amount_deviation
    ]])

def train_and_predict(username, amount, transactionId, userId, ip, userAgent):
    """Train Isolation Forest and predict anomaly."""
    try:
        user, analytics = fetch_user_data(username)
        
        # Prepare features
        features = prepare_features(user, analytics, amount, ip, userAgent)
        
        # Load or train model (in production, use pre-trained model)
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(features)  # Placeholder; ideally load pre-trained model
        
        # Predict anomaly (-1 for anomaly, 1 for normal)
        prediction = model.predict(features)[0]
        is_anomaly = prediction == -1
        
        # Rule-based checks for BoZ compliance
        if (amount > 10000 or
            deposit_count_24h >= 5 or
            withdrawal_count_24h >= 5 or
            user.get('depositAttempts', 0) >= 5 or
            user.get('lastWithdrawAttempts', 0) >= 5):
            is_anomaly = True
        
        # Log to Analytics
        analytics_entry = db.analytics.insert_one({
            'event': 'fraud_prediction',
            'identifier': username,
            'data': {
                'transactionId': transactionId,
                'userId': str(userId),
                'amount': amount,
                'is_anomaly': is_anomaly,
                'ip': ip,
                'userAgent': userAgent,
                'features': {
                    'deposit_count_24h': deposit_count_24h,
                    'withdrawal_count_24h': withdrawal_count_24h,
                    'avg_deposit_amount': float(avg_deposit_amount),
                    'avg_transaction_amount': float(avg_transaction_amount),
                    'analytics_count': analytics_count,
                    'error_count': error_count,
                    'deposit_attempts': deposit_attempts,
                    'withdraw_attempts': withdraw_attempts,
                    'ip_entropy': ip_entropy,
                    'ua_entropy': ua_entropy,
                    'amount_deviation': float(amount_deviation)
                }
            },
            'timestamp': datetime.now()
        })
        
        logger.info(f'[FraudDetection] Prediction for {username}: is_anomaly={is_anomaly}, analyticsEventId={analytics_entry.inserted_id}')
        return {
            'is_anomaly': is_anomaly,
            'analyticsEventId': str(analytics_entry.inserted_id)
        }
    except Exception as e:
        logger.error(f'[FraudDetection] Error predicting fraud: {e}')
        analytics_entry = db.analytics.insert_one({
            'event': 'fraud_prediction_failed',
            'identifier': username,
            'data': {
                'error': str(e),
                'transactionId': transactionId,
                'userId': str(userId),
                'amount': amount,
                'ip': ip,
                'userAgent': userAgent
            },
            'timestamp': datetime.now()
        })
        return {
            'error': str(e),
            'analyticsEventId': str(analytics_entry.inserted_id)
        }

@app.route('/predict', methods=['POST'])
def predict():
    """Fraud detection endpoint."""
    try:
        data = request.get_json()
        required_fields = ['username', 'amount', 'transactionId', 'userId', 'timestamp', 'ip', 'userAgent']
        if not data or not all(field in data for field in required_fields):
            logger.error(f'[FraudDetection] Invalid request data: {data}')
            analytics_entry = db.analytics.insert_one({
                'event': 'fraud_prediction_failed',
                'identifier': data.get('username', 'unknown'),
                'data': {
                    'error': 'Missing required fields',
                    'received_data': data
                },
                'timestamp': datetime.now()
            })
            return jsonify({
                'error': 'Missing required fields',
                'analyticsEventId': str(analytics_entry.inserted_id)
            }), 400
        
        username = data['username']
        amount = float(data['amount'])
        transactionId = data['transactionId']
        userId = data['userId']
        ip = data['ip']
        userAgent = data['userAgent']
        
        result = train_and_predict(username, amount, transactionId, userId, ip, userAgent)
        return jsonify(result), 200 if 'error' not in result else 500
    except Exception as e:
        logger.error(f'[FraudDetection] Endpoint error: {e}')
        analytics_entry = db.analytics.insert_one({
            'event': 'fraud_prediction_failed',
            'identifier': data.get('username', 'unknown') if 'data' in locals() else 'unknown',
            'data': {
                'error': str(e),
                'received_data': data if 'data' in locals() else {}
            },
            'timestamp': datetime.now()
        })
        return jsonify({
            'error': str(e),
            'analyticsEventId': str(analytics_entry.inserted_id)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # Production: use Gunicorn