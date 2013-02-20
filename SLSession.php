<?php
/**
 * 
 * Storeless user sessions.
 * 
 * Interface:
 * 
 * create( <id_user>, <remember_me> )
 * 
 * is_alive(): returns false or the id_user
 * 
 * destroy(): it just remove the session cookie, the session can't be destroyed, it just expires.
 * 
 * set_config( <array> ): setting config parameters.
 */

class SLSession {
	private static $session_password_previous = null;
	private static $session_password_current = null;
	private static $session_id_name = 's';

	private static $session_time_frame_seconds = 180; // 3 Minutes
	private static $remember_me_expiricy_days = 7; // Session expiricy, 1 week of remember me.
	private static $not_remember_me_expiricy_minutes = 25; // Session expiricy, 25 minutes for not remember me.
	
	private static $banned_session_id_users = array(); // Associative array with banned id users as keys.
	
	// Extra security forcing to match the first octect of the ip, some users might have several ips
	// so though you just match the first octect it wouldn't work.
	private static $first_octect_ip_match = false; 
	
	private static $id_user = 0;
	private static $remember_me = false;
	private static $last_visit_time = 0;
	private static $is_alive = null;
	private static $is_expired = null;
	private static $hash_with_previous_password = false;
	
	const SESSION_ID_VALUE_FORMAT = '%d,%d,%d,%s';

	private function __construct( ) { }
	
	public static function set_config( array $config ) {
		$config_keys = array(
							'session_password_previous' => 1,
							'session_password_current' => 1,
							'session_id_name' => 1,
							'session_time_frame_seconds' => 1,
							'remember_me_expiricy_days' => 1,
							'not_remember_me_expiricy_minutes' => 1,
							'first_octect_ip_match' => 1,
							'banned_session_id_users' => 1,
							);
		foreach ( $config as $name => $value ) {
			if ( array_key_exists($name, $config_keys) ) {
				self::$$name = $value;
			} else {
				throw new SLSLSessionException(sprintf('Config name "%s" is not valid', $name));
			}
		}
	}
	
	public static function create( $id_user, $remember_me = false ) {
		//The only way to "erase" a session is setting its id_user in the gobal $BANNED_ID_USER_SESSION.
		//If the id_user is set we return false.
		if ( isset(self::$banned_sesssion_id_users) && isset(self::$banned_sesssion_id_users[$id_user]) ) {
			return false;
		}
		
		$last_visit_time = time();
		
		if ( null === self::$session_password_current ) {
			throw new SLSLSessionException('A password is required for the session.');
		}
		$session_hash = self::build_session_hash($id_user, $last_visit_time, $remember_me  === true ? '1' : '0', self::$session_password_current);
		self::set_cookie(self::$session_id_name, sprintf(self::SESSION_ID_VALUE_FORMAT, $id_user, $remember_me , $last_visit_time, $session_hash), $remember_me === true ? self::$remember_me_expiricy_days : null, null, false, true);
		self::$id_user = (int) $id_user;
		self::$is_alive = true;
	}
	
	public static function is_alive() {		
		if ( self::$is_alive !== null ) {
			return self::$is_alive;
		}
		
		if ( ! isset($_COOKIE[self::$session_id_name ]) ) {
			self::$is_alive = false;
			return false;
		}
		
		$tokens = explode(',', $_COOKIE[self::$session_id_name] );
		if ( count($tokens) !== 4 ) {
			// Probable hack attempt.
			self::destroy();
			self::$is_alive = false;
			return false;
		}
		
		list($id_user, $remember_me , $last_visit_time, $session_hash) = $tokens;
		
		//The only way to "erase" a session is setting its id_user in the gobal $BANNED_ID_USER_SESSION.
		//If the id_user is set we return false.
		if ( isset(self::$banned_sesssion_id_users) && isset(self::$banned_sesssion_id_users[$id_user]) ) {
			self::$is_alive = false;
			return false;
		}
		
		$hash_current_session_password = self::build_session_hash($id_user, $last_visit_time, $remember_me, self::$session_password_current);

		if ( $session_hash !== $hash_current_session_password ) {
			/**
			 * After changing the session password the users have hashes generated with the previous password
			 * so we check if it match the hash with the previous session password ( if it is set ).
			 * If it does, we regenerate the hash with the new session password.
			 */
			$hash_previous_session_password = null;
			if ( null !== self::$session_password_previous ) {
				$hash_previous_session_password = self::build_session_hash($id_user, $last_visit_time, $remember_me, self::$session_password_previous);
			}
			if ( $session_hash === $hash_previous_session_password )	{
				/**
				 * The user has a session generated with the previous password.
				 * That's ok but lets set the "hash with previous password" so the keep_alive method
				 * regenerates the session hash with the new password.
				 */
				self::$hash_with_previous_password = True;
			} else {
				//This would be a hack attempt
				self::destroy();
				self::$is_alive = false;
				return false;
			}
		}
		
		//Checking if it has expired
		
		if ( $remember_me  === '1' ) {
			$max_time = self::$remember_me_expiricy_days * 86400;
		} else {
			$max_time = self::$not_remember_me_expiricy_minutes * 60;
		}
		
		self::$last_visit_time = (int) $last_visit_time;
		
		if ( ( self::$last_visit_time + $max_time ) < time() ) {
			//It has expired
			self::destroy();
			self::$is_alive = false;
			self::$is_expired = true;
			return false;
		} 
		
		self::$is_expired = false;
		self::$is_alive = true;
		
		self::$id_user = (int) $id_user;
		self::$remember_me = $remember_me === '1' ? true : false;
		
		return true;
	}
	
	/**
	 * @return null if it's never being alive, true, if it was alive but not now, false if it's alive now.
	 */
	public static function is_expired() {
		// Check if it's alive.
		if ( self::$is_expired === null ) {
			self::is_alive();
		}
		return self::$is_expired;
	}
	
	public static function keep_alive() {
		if ( self::$is_alive ) {
			// With time frames we avoid setting a new session cookie each request
			// With the modulos of the $id_user we spread the cookie and last_visit_time update along the time_frame
			$ts = time() + ( self::$id_user % self::$session_time_frame_seconds );
			$current_time_frame = $ts - ( $ts % self::$session_time_frame_seconds );
			
			$last_visit_time_frame = self::$last_visit_time - ( self::$last_visit_time % self::$session_time_frame_seconds );
			
			if ( $current_time_frame !== $last_visit_time_frame || self::$hash_with_previous_password ) {
				self::create(self::$id_user, self::$remember_me);
			}
		}
	}
	
	public static function destroy() {
		// I set is alive to false in case the Session is used after is destroyed in the same request.
		// Like in the logout case and after checking if it's alive to get the user credits notifications and statics files revisions.
		self::$is_alive = false;
		self::$is_expired = false;
		
		//The session can't really be destroyed because it's not stored.
		//It's just not usable after the expiricy time.
		//All we can do is remove the cookie.
		
		self::delete_cookie(self::$session_id_name, null, false, true);
		//It's necessary to solve cookie conflicts between aps and environments aswell.
		$host_tokens = explode('.', $_SERVER['HTTP_HOST']);
		$host_tokens_length = count($host_tokens);
		$new_host_tokens = array_slice($host_tokens, $host_tokens_length - 2, 2);
		self::delete_cookie(self::$session_id_name, implode('.', $new_host_tokens), false, true);
	}
	
	public static function get_id_user() {
		return self::$id_user;
	}
	
	private static function build_session_hash( $id_user, $last_visit_time, $remember_me, $session_password ) {
		if ( self::$first_octect_ip_match ) {
			list($ip_first_octect) = explode('.', $_SERVER['REMOTE_ADDR']);
		} else {
			// Some people at work uses several internet providers doing request from several ips so we can take the first octect even.
			$ip_first_octect = '';
		}
		$user_agent = '';
		if ( array_key_exists('HTTP_USER_AGENT', $_SERVER ) ) {
			$user_agent = $_SERVER['HTTP_USER_AGENT'];
		}
		return hash('sha256', $session_password.$id_user.$last_visit_time.$remember_me.$user_agent.$ip_first_octect);
	}
	
	private static function set_cookie( $name, $value, $days=null, $domain=null, $secure=false, $http_only=false ) {
		//Session cookie
		$path = '/';
		if ( $domain === null ) {
			$host_tokens = explode('.', $_SERVER['HTTP_HOST']);
			$new_host_tokens = array();
			// Cut domains on sub-subdomains.
			for ( $x = 0; $x < 3; ++$x ) {
				if ( 0 === count($host_tokens) ) {
					break;
				}
				array_unshift($new_host_tokens, array_pop($host_tokens) );
			}
			$domain = implode('.', $new_host_tokens);
		}
		if ( $days === null ) {
			$expires = null;
		} else {
			//86400 seconds = 1 day
			$expires = time() + ( $days * 86400 );
		}
		setcookie($name, $value, $expires, $path, $domain, $secure, $http_only);
	}
	
	private static function delete_cookie( $name, $domain=null, $secure=false, $http_only=false ) {
		self::set_cookie($name, '', -100, $domain, $secure, $http_only);
	}
}

class SLSLSessionException extends Exception { }