const validatePassword = (password) => {
    const pattern =
        /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{6,16}$/;
    if (pattern.test(password)) {
        return true;
    } else {
        return false;
    }
};

export default validatePassword;
