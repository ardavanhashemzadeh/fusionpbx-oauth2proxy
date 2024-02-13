<?php
/**
* plugin_oauth2proxy 
* Authentication plugin for authenticating using headers from oauth2_proxy
* By Ardy Hash based on plugin_msad_ldap found on pbxforums.com
*
* @method oauth2proxy uses headers passed by proxy to authenticate user
*/
class plugin_oauth2proxy {
  /**
  * Define variables and their scope
  */
  public $debug;
  public $domain_name;
  public $username;
  public $password;
  public $user_uuid;
  public $contact_uuid;

  /**
  * oauth2proxy checks proxy headers against database to authenticate the user
  * @return array [authorized] => true or false
  **/
  function oauth2proxy() {
//save the database connection to a local variable
  include "root.php";
  require_once "resources/classes/database.php";
  $database = new database;
  $database->connect();
  $db = $database->db;
//use headers to validate the user authentication
  $user_authorized = false;
  $headers = getallheaders();
  if(array_key_exists('X-Access-Token', $headers) && array_key_exists('X-User', $headers) && array_key_exists('X-Email', $headers)) {
    if($headers['X-Access-Token'] != '' && $headers['X-User'] != '' && $headers['X-Email'] != '') {
      $sql = "select * from v_users where user_enabled='true' ";
      $sql .= "and user_email=:useremail ";
      if ($_SESSION["user"]["unique"]["text"] == "global") {
        //unique username - global (example: email address)
      }
      else {
        //unique username - per domain
        $sql .= "and domain_uuid=:domain_uuid ";
      }
      $prep_statement = $db->prepare(check_sql($sql));
      if ($_SESSION["user"]["unique"]["text"] != "global") {
        $prep_statement->bindParam(':domain_uuid', $this->domain_uuid);
      }
      $prep_statement->bindParam(':useremail', $headers['X-Email']);
      $prep_statement->execute();
      $user_results = $prep_statement->fetchAll(PDO::FETCH_NAMED);
      if (count($user_results) > 0) {
        $user_authorized = true;
        foreach ($user_results as &$row) {
          if ($_SESSION["user"]["unique"]["text"] == "global" && $row["domain_uuid"] != $this->domain_uuid) {
            //get the domain uuid
              $this->domain_uuid = $row["domain_uuid"];
              $this->domain_name = $_SESSION['domains'][$this->domain_uuid]['domain_name'];
          }

        //set the domain session variables
          $_SESSION["domain_uuid"] = $this->domain_uuid;
          $_SESSION["domain_name"] = $this->domain_name;

        //set the setting arrays
          $domain = new domains();
          $domain->db = $db;
          $domain->set();
          $this->username = $row["username"];
          $this->user_uuid = $row["user_uuid"];
          $this->contact_uuid = $row["contact_uuid"];
        }
      }
    }
  }
  $_SESSION["username"] = $this->username;
  $result["plugin"] = "oauth2proxy";
  $result["username"] = $this->username;
  $result["user_uuid"] = $this->user_uuid;
  $result["domain_uuid"] = $this->domain_uuid;
  $result["domain_name"] = $this->domain_name;
  if ($this->debug) {
    $result["password"] = $this->password;
  }
  if ($user_authorized) {
      $result["authorized"] = "true";
  } else {
     $result["authorized"] = "false";
  }
  return $result;
  }
}
?>
