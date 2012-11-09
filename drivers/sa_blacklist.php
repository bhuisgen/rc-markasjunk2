<?php

/**
 * SpamAssassin Blacklist driver
 * @version 2.0
 * @requires SAUserPrefs plugin
 * @author Philip Weir
 */

class markasjunk2_sa_blacklist
{
	public function spam($uids)
	{
		$this->_do_list($uids, true);
	}

	public function ham($uids)
	{
		$this->_do_list($uids, false);
	}

	private function _do_list($uids, $spam)
	{
		$rcmail = rcmail::get_instance();
		if (!$rcmail->config->get('sauserprefs_db_dsnw')) {
			write_log('errors', 'plugin sauserprefs not loaded');
			
			return false;
        }
		

		$db = new rcube_mdb2($rcmail->config->get('sauserprefs_db_dsnw'), $rcmail->config->get('sauserprefs_db_dsnr'), $rcmail->config->get('sauserprefs_db_persistent'));
		$db->set_debug((bool)rcmail::get_instance()->config->get('sql_debug'));
		$db->db_connect('w');

		// check DB connections and exit on failure
		if ($err_str = $db->is_error()) {
			raise_error(array(
				'code' => 603,
				'type' => 'db',
				'message' => $err_str), FALSE, TRUE);
		}

		foreach (explode(",", $uids) as $uid) {
			$message = new rcube_message($uid);
			$email = $message->sender['mailto'];

			if ($spam) {
				// delete any whitelisting for this address
				$db->query(
					"DELETE FROM ". $rcmail->config->get('sauserprefs_sql_table_name') ." WHERE ". $rcmail->config->get('sauserprefs_sql_username_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_preference_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_value_field') ." = ?;",
					$_SESSION['username'],
					'whitelist_from',
					$email);

				// check address is not already blacklisted
				$sql_result = $db->query(
								"SELECT value FROM ". $rcmail->config->get('sauserprefs_sql_table_name') ." WHERE ". $rcmail->config->get('sauserprefs_sql_username_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_preference_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_value_field') ." = ?;",
								$_SESSION['username'],
								'blacklist_from',
								$email);

				if ($db->num_rows($sql_result) == 0) {
					$db->query(
						"INSERT INTO ". $rcmail->config->get('sauserprefs_sql_table_name') ." (". $rcmail->config->get('sauserprefs_sql_username_field') .", ". $rcmail->config->get('sauserprefs_sql_preference_field') .", ". $rcmail->config->get('sauserprefs_sql_value_field') .") VALUES (?, ?, ?);",
						$_SESSION['username'],
						'blacklist_from',
						$email);

					if ($rcmail->config->get('markasjunk2_debug'))
						write_log('markasjunk2', $_SESSION['username'] . ' blacklist ' . $email);
				}
			}
			else {
				// delete any blacklisting for this address
				$db->query(
					"DELETE FROM ". $rcmail->config->get('sauserprefs_sql_table_name') ." WHERE ". $rcmail->config->get('sauserprefs_sql_username_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_preference_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_value_field') ." = ?;",
					$_SESSION['username'],
					'blacklist_from',
					$email);

				// check address is not already whitelisted
				$sql_result = $db->query(
								"SELECT value FROM ". $rcmail->config->get('sauserprefs_sql_table_name') ." WHERE ". $rcmail->config->get('sauserprefs_sql_username_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_preference_field') ." = ? AND ". $rcmail->config->get('sauserprefs_sql_value_field') ." = ?;",
								$_SESSION['username'],
								'whitelist_from',
								$email);

				if ($db->num_rows($sql_result) == 0) {
					$db->query(
						"INSERT INTO ". $rcmail->config->get('sauserprefs_sql_table_name') ." (". $rcmail->config->get('sauserprefs_sql_username_field') .", ". $rcmail->config->get('sauserprefs_sql_preference_field') .", ". $rcmail->config->get('sauserprefs_sql_value_field') .") VALUES (?, ?, ?);",
						$_SESSION['username'],
						'whitelist_from',
						$email);

					if ($rcmail->config->get('markasjunk2_debug'))
						write_log('markasjunk2', $_SESSION['username'] . ' whitelist ' . $email);
				}
			}
		}
	}
}

?>