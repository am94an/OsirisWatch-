import React from 'react';

// مكون لعرض قائمة الإشعارات
const NotificationList = ({ notifications }) => {
    return (
        <div>
            <h2>قائمة الإشعارات</h2>
            {notifications.length === 0 ? (
                <p>لا توجد إشعارات.</p>
            ) : (
                notifications.map(notification => (
                    <div key={notification.id} className="notification">
                        <p><strong>الرسالة:</strong> {notification.message}</p>
                        <p><strong>النوع:</strong> {notification.notification_type}</p>
                        <p><strong>الحالة:</strong> {notification.is_read ? 'مقروءة' : 'غير مقروءة'}</p>
                        <p><strong>تاريخ الإرسال:</strong> {new Date(notification.sent_at).toLocaleString()}</p>
                    </div>
                ))
            )}
        </div>
    );
};

export default NotificationList;
