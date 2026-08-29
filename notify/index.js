// Notification service placeholder
// TODO: Implement actual notification service

console.log('Notification service loaded');

module.exports = {
  sendNotification: (message) => {
    console.log(`[NOTIFICATION] ${message}`);
    return true;
  }
};
