// Email validation
export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Password validation - requires at least 8 chars, one uppercase, one lowercase, one number
export const validatePassword = (password) => {
  // Password should be at least 8 characters with at least one uppercase, one lowercase, and one number
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d\w\W]{8,}$/;
  return passwordRegex.test(password);
};

// Password match validation
export const validatePasswordMatch = (password, confirmPassword) => {
  return password === confirmPassword;
};

// Username validation - 3-30 characters, alphanumeric with underscores
export const validateUsername = (username) => {
  // Username should be 3-30 characters, alphanumeric with underscores
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  return usernameRegex.test(username);
};

// Required field validation
export const validateRequired = (value) => {
  return value !== undefined && value !== null && value.trim() !== '';
};

// IP address validation
export const validateIPAddress = (ip) => {
  const regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return regex.test(ip);
};

// Phone number validation
export const validatePhoneNumber = (phone) => {
  // Basic phone number validation - can be customized based on requirements
  const phoneRegex = /^\+?[\d\s-]{10,}$/;
  return !phone || phoneRegex.test(phone);
};

// Form field validation with support for multiple validation rules
export const validateField = (value, validations = []) => {
  const errors = [];
  
  validations.forEach(validation => {
    switch (validation) {
      case 'required':
        if (!validateRequired(value)) {
          errors.push('This field is required');
        }
        break;
      case 'email':
        if (value && !validateEmail(value)) {
          errors.push('Please enter a valid email address');
        }
        break;
      case 'username':
        if (value && !validateUsername(value)) {
          errors.push('Username must be at least 3 characters and can only contain letters, numbers, and underscores');
        }
        break;
      case 'ipAddress':
        if (value && !validateIPAddress(value)) {
          errors.push('Please enter a valid IP address');
        }
        break;
      default:
        break;
    }
  });
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Full form validation
export const validateForm = (formData, validationRules) => {
  const errors = {};
  let isValid = true;
  
  Object.keys(validationRules).forEach(field => {
    const fieldValidation = validateField(formData[field], validationRules[field]);
    if (!fieldValidation.isValid) {
      errors[field] = fieldValidation.errors;
      isValid = false;
    }
  });
  
  return { isValid, errors };
};

export const validateRole = (role, availableRoles) => {
  return availableRoles.includes(role);
};

