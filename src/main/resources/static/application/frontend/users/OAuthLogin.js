var OAuthLogin = (props) => {
    if(location.hash) {
        const hash = window.location.hash.substring(1);
        const params = {};
        const handleParams = () => {
            const paramsHash = new URLSearchParams(hash);
            params.access_token =  paramsHash.get("access_token");
        }
        handleParams();

        if(params.access_token) {
            var jwtToken = jwt.parseJwtToken(params.access_token);
            jwt.storeJwtToken(params.access_token);
            props.dispatch({
                type: 'login',
                user: jwtToken.user_name,
                authorities: jwtToken.authorities,
                token: params.access_token
            });
            return (<ReactRouterDOM.Redirect to="/"/>);
        }
    }
    alerts.error('Access denied!');
    return (<ReactRouterDOM.Redirect to="/login"/>);
};
OAuthLogin = ReactRedux.connect()(OAuthLogin);

