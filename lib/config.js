
let config = {
    JWT_SECRET_KEY: process.env.JWT_SECRET_KEY || 'qwertyuiolkjhgfdsazxcvbnm234567890uytrew', // Default value for local development
    GOOGLE_CLIENT_ID: process.env.JWT_SECRET_KEY,
    EMAIL_FOR_OTP: false
};

const setConfig = (options) => {
    config = { ...config, ...options };
};

const getConfig = () => config;

module.exports = {
    setConfig,
    getConfig,
};






    // let JWT_SECRET_KEY, GOOGLE_CLIENT_ID;
    
    // const config = (data) => {
    //     JWT_SECRET_KEY = data.JWT_SECRET_KEY || 'qwertyuioljhgfdszxcvbnmsdfghtyuiokgf';
    //     GOOGLE_CLIENT_ID = data.GOOGLE_CLIENT_ID || 'not found';
    //     console.log(JWT_SECRET_KEY);
    //     console.log(GOOGLE_CLIENT_ID);
        
    //     return (req, res, next) => {
    //         req.JWT_SECRET_KEY=JWT_SECRET_KEY
    //         req.GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID
    //     };
    //         next();
    // };
    
    // module.exports = { config };