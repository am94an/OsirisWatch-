// Default permissions for each role
export const defaultPermissionsForRole = (role) => {
  const basePermissions = {
    dashboard: { read: false, write: false, delete: false },
    reports: { read: false, write: false, delete: false },
    users: { read: false, write: false, delete: false },
    settings: { read: false, write: false, delete: false }
  };

  switch (role) {
    case 'Super Admin':
      return {
        dashboard: { read: true, write: true, delete: true },
        reports: { read: true, write: true, delete: true },
        users: { read: true, write: true, delete: true },
        settings: { read: true, write: true, delete: true }
      };
    case 'Admin':
      return {
        dashboard: { read: true, write: true, delete: false },
        reports: { read: true, write: true, delete: false },
        users: { read: true, write: true, delete: false },
        settings: { read: true, write: true, delete: false }
      };
    case 'Analyst':
      return {
        dashboard: { read: true, write: true, delete: false },
        reports: { read: true, write: true, delete: false },
        users: { read: true, write: false, delete: false },
        settings: { read: true, write: false, delete: false }
      };
    case 'Viewer':
      return {
        dashboard: { read: true, write: false, delete: false },
        reports: { read: true, write: false, delete: false },
        users: { read: true, write: false, delete: false },
        settings: { read: true, write: false, delete: false }
      };
    default:
      return basePermissions;
  }
};

// Check if user has specific permission
export const hasPermission = (userPermissions, module, action) => {
  if (!userPermissions || !userPermissions[module]) {
    return false;
  }
  return userPermissions[module][action] || false;
};

// Check if user has any permission in a module
export const hasAnyPermission = (userPermissions, module) => {
  if (!userPermissions || !userPermissions[module]) {
    return false;
  }
  return Object.values(userPermissions[module]).some(value => value);
};

// Check if user has all permissions in a module
export const hasAllPermissions = (userPermissions, module) => {
  if (!userPermissions || !userPermissions[module]) {
    return false;
  }
  return Object.values(userPermissions[module]).every(value => value);
};

// Get available roles based on current user's permissions
export const getAvailableRoles = (currentUserPermissions) => {
  const roles = ['Viewer'];
  
  if (hasPermission(currentUserPermissions, 'users', 'write')) {
    roles.push('Analyst');
  }
  
  if (hasPermission(currentUserPermissions, 'users', 'delete')) {
    roles.push('Admin');
    roles.push('Super Admin');
  }
  
  return roles;
};

// Format permissions for API
export const formatPermissionsForAPI = (permissions) => {
  return {
    dashboard: {
      read: permissions.dashboard.read,
      write: permissions.dashboard.write,
      delete: permissions.dashboard.delete
    },
    reports: {
      read: permissions.reports.read,
      write: permissions.reports.write,
      delete: permissions.reports.delete
    },
    users: {
      read: permissions.users.read,
      write: permissions.users.write,
      delete: permissions.users.delete
    },
    settings: {
      read: permissions.settings.read,
      write: permissions.settings.write,
      delete: permissions.settings.delete
    }
  };
}; 