const notificationService = require('./index');

describe('Notification Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    console.log.mockRestore();
  });

  describe('sendNotification', () => {
    test('should send notification successfully', () => {
      const result = notificationService.sendNotification('Test message');
      expect(result).toBe(true);
    });

    test('should log notification with correct format', () => {
      notificationService.sendNotification('Security Alert');
      expect(console.log).toHaveBeenCalledWith('[NOTIFICATION] Security Alert');
    });

    test('should handle empty message', () => {
      const result = notificationService.sendNotification('');
      expect(result).toBe(true);
      expect(console.log).toHaveBeenCalledWith('[NOTIFICATION] ');
    });

    test('should handle long messages', () => {
      const longMessage = 'x'.repeat(1000);
      const result = notificationService.sendNotification(longMessage);
      expect(result).toBe(true);
    });

    test('should handle special characters in message', () => {
      const specialMessage = 'Alert: "CRITICAL" [ERROR] <injection>';
      const result = notificationService.sendNotification(specialMessage);
      expect(result).toBe(true);
      expect(console.log).toHaveBeenCalledWith(`[NOTIFICATION] ${specialMessage}`);
    });

    test('should return true for all notifications', () => {
      const messages = [
        'scan.created',
        'scan.updated',
        'vulnerability.detected',
        'remediation.completed',
      ];

      messages.forEach(msg => {
        const result = notificationService.sendNotification(msg);
        expect(result).toBe(true);
      });
    });
  });

  describe('Module exports', () => {
    test('should export sendNotification function', () => {
      expect(typeof notificationService.sendNotification).toBe('function');
    });

    test('should be an object with sendNotification method', () => {
      expect(notificationService).toHaveProperty('sendNotification');
      expect(Object.keys(notificationService).length).toBe(1);
    });
  });
});
