const { Expo } = require('expo-server-sdk');
const expo = new Expo();

async function sendPushNotification(pushToken, message) {
  if (!Expo.isExpoPushToken(pushToken)) return;
  const messages = [{
    to: pushToken,
    sound: 'default',
    body: message,
    data: { type: 'payment_received' },
  }];
  await expo.sendPushNotificationsAsync(messages);
}

module.exports = { sendPushNotification };