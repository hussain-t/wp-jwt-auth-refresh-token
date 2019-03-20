<?php

/** Requiere the JWT library. */
use \Firebase\JWT\JWT;

/**
 * The public-facing functionality of the plugin.
 *
 * @link       https://enriquechavez.co
 * @since      1.0.0
 */

/**
 * The public-facing functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @author     Enrique Chavez <noone@tmeister.net>
 */
class Jwt_Auth__Extention_Public
{
    /**
     * The ID of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The current version of this plugin.
     */
    private $version;

    /**
     * The namespace to add to the api calls.
     *
     * @var string The namespace to add to the api call
     */
    private $namespace;

    /**
     * Store errors to display if the JWT is wrong
     *
     * @var WP_Error
     */
    private $jwt_error = null;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     *
     * @param string $plugin_name The name of the plugin.
     * @param string $version     The version of this plugin.
     */
    public function __construct()
    {
        add_action('rest_api_init', array($this, 'jwt_auth_refresh_add_api_routes'));
    }

    /**
     * Add the endpoints to the API
     */
    public function jwt_auth_refresh_add_api_routes()
    {
        register_rest_route('jwt-auth/v1', 'token/refresh', array(
            'methods' => 'POST',
            'callback' => array($this, 'jwt_auth_refresh_token'),
        ));
    }

    /**
     * jwt_auth_refresh_token
     */
    public function jwt_auth_refresh_token(WP_REST_Request $request)
    {

        $body = $request->get_body();
        $parameters = json_decode($body);
        //$token = $parameters['token'];

        $token = $parameters->token;
        $email = $parameters->email;

        /*
         * The HTTP_AUTHORIZATION is present verify the format
         * if the format is wrong return the user.
         */

        /** Get the Secret Key */
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Try to decode the token */
        //try {

        try {
            $token = JWT::decode($token, $secret_key, array('HS256'));

            /** The Token is decoded now validate the iss */
            if ($token->iss != get_bloginfo('url')) {
                /** The iss do not match, return error */
                return new WP_Error(
                    'jwt_auth_bad_iss',
                    __('The iss do not match with this server', 'wp-api-jwt-auth'),
                    array(
                        'status' => 403,
                    )
                );
            }
            /** So far so good, validate the user id in the token */
            if (!isset($token->data->user->id)) {
                /** No user id in the token, abort!! */
                return new WP_Error(
                    'jwt_auth_bad_request',
                    __('User ID not found in the token', 'wp-api-jwt-auth'),
                    array(
                        'status' => 403,
                    )
                );
            }

        } catch (Exception $e) {
            $className = get_class($e);

            if ($className == "Firebase\\JWT\\ExpiredException") {
                $user = get_user_by('email', $email);

                if (!$user) {
                    return new WP_Error(
                        'jwt_auth_invalid_email',
                        'Email not found',
                        array(
                            'status' => 403,
                        )
                    );
                }

                $issuedAt = time();
                $notBefore = apply_filters('jwt_auth_not_before', $issuedAt, $issuedAt);
                $expire = apply_filters('jwt_auth_expire', $issuedAt + (DAY_IN_SECONDS * 7), $issuedAt);

                $token = array(
                    'iss' => get_bloginfo('url'),
                    'iat' => $issuedAt,
                    'nbf' => $notBefore,
                    'exp' => $expire,
                    'data' => array(
                        'user' => array(
                            'id' => $user->data->ID,
                        ),
                    ),
                );

                /** Let the user modify the token data before the sign. */
                $token = JWT::encode(apply_filters('jwt_auth_token_before_sign', $token, $user), $secret_key);

                /** The token is signed, now create the object with no sensible user data to the client*/
                $data = array(
                    'token' => $token,
                    'user_email' => $user->data->user_email,
                    'user_nicename' => $user->data->user_nicename,
                    'user_display_name' => $user->data->display_name,
                );

                /** Let the user modify the data before send it back */
                return apply_filters('jwt_auth_token_before_dispatch', $data, $user);
            }
        }

        return $auth;
    }
}
