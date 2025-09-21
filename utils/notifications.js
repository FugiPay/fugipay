const { Expo } = require('expo-server-sdk');
const Analytics = require('./models/Analytics');

const expo = new Expo();

// Retry logic for sending notifications
const sendWithRetry = async (messages, retries = 3, baseDelay = 2000) => {
  let lastError;
  for (let i = 0; i <= retries; i++) {
    try {
      console.log(`[Notification] Sending - Attempt ${i + 1}/${retries + 1}`);
      const tickets = await expo.sendPushNotificationsAsync(messages);
      console.log('[Notification] Tickets:', tickets);
      return tickets;
    } catch (error) {
      lastError = error;
      if (i === retries || error.message.includes('Invalid push token')) {
        console.log(`[Notification] Aborted: ${error.message}`);
        break;
      }
      const delay = baseDelay * Math.pow(2, i) + Math.random() * 1000;
      console.log(`[Notification] Retry ${i + 1}/${retries} after ${Math.round(delay)}ms`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw lastError;
};

async function sendPushNotification(pushToken, title, message, data = {}, identifier = 'unknown') {
  if (!Expo.isExpoPushToken(pushToken)) {
    console.error('[Notification] Invalid push token:', pushToken);
    const analytics = await new Analytics({
      event: 'notification_failed',
      identifier,
      data: {
        error: 'Invalid push token',
        pushToken,
        notificationType: data.type || 'unknown',
        title,
        message,
      },
      timestamp: new Date(),
    }).save();
    return { error: 'Invalid push token', analyticsEventId: analytics._id };
  }

  const notificationData = {
    type: data.type || 'general',
    userId: data.userId || null,
    transactionId: data.transactionId || null,
    withdrawalIndex: data.withdrawalIndex || null,
    depositId: data.depositId || null,
    kycStatus: data.kycStatus || null,
    analyticsEventId: data.analyticsEventId || null,
    ip: data.ip || null,
    userAgent: data.userAgent || null,
  };

  const messages = [{
    to: pushToken,
    sound: 'default',
    title,
    body: message,
    data: notificationData,
    priority: 'high',
  }];

  try {
    const tickets = await sendWithRetry(messages);
    const ticket = tickets[0];
    if (ticket.status === 'error') {
      const analytics = await new Analytics({
        event: 'notification_failed',
        identifier,
        data: {
          error: ticket.details?.error || 'Unknown error',
          pushToken,
          notificationType: notificationData.type,
          title,
          message,
          details: ticket.details,
        },
        timestamp: new Date(),
      }).save();
      return { error: ticket.details?.error || 'Failed to send notification', analyticsEventId: analytics._id };
    }

    const analytics = await new Analytics({
      event: 'notification_sent',
      identifier,
      data: {
        pushToken,
        notificationType: notificationData.type,
        title,
        message,
        userId: notificationData.userId,
        transactionId: notificationData.transactionId,
        withdrawalIndex: notificationData.withdrawalIndex,
        depositId: notificationData.depositId,
        kycStatus: notificationData.kycStatus,
        ip: notificationData.ip,
        userAgent: notificationData.userAgent,
      },
      timestamp: new Date(),
    }).save();

    console.log('[Notification] Success:', { pushToken, notificationType: notificationData.type, analyticsEventId: analytics._id });
    return { success: true, analyticsEventId: analytics._id };
  } catch (error) {
    console.error('[Notification] Error:', {
      message: error.message,
      stack: error.stack,
      pushToken,
      notificationType: notificationData.type,
    });
    const analytics = await new Analytics({
      event: 'notification_failed',
      identifier,
      data: {
        error: error.message,
        pushToken,
        notificationType: notificationData.type,
        title,
        message,
        userId: notificationData.userId,
        transactionId: notificationData.transactionId,
        withdrawalIndex: notificationData.withdrawalIndex,
        depositId: notificationData.depositId,
        kycStatus: notificationData.kycStatus,
        ip: notificationData.ip,
        userAgent: notificationData.userAgent,
      },
      timestamp: new Date(),
    }).save();
    return { error: error.message, analyticsEventId: analytics._id };
  }
}

module.exports = { sendPushNotification };