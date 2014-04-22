<?php
/**
* ProjectHoneyPot
* Check an IP Against the Project Honey Pot Blacklist (https://www.projecthoneypot.org)
* @author Jeremy M. Usher <jeremy@firefly.us>
* @copyright 2014 Jeremy M. Usher 
* @category Security
* @version 0.90
* @license http://opensource.org/licenses/MIT MIT License
*
*/
class ProjectHoneyPot {
    

	const SEARCH_DOMAIN		= 'dnsbl.httpbl.org';
	const NOT_FOUND			= '127.0.0.1';
	
	const SEARCH_ENGINE 	= 0;
	const SUSPICIOUS		= 1;
	const HARVESTER  		= 2;
	const COMMENT_SPAMMER	= 3;


	protected $access_key;
	protected $ip;
	protected $raw_response;
	protected $response;
	protected $threat_score;
	protected $visitor_type;
	protected $last_activity;
	protected $search_host;



	/**
	* Instantiate the ProjectHoneyPot class.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('173.194.46.102', $apikey);
	* 	$result = $h->isSuspicous(); // returns FALSE
	* </code>
	*
	* @param String $ip The IP address to be checked against the Project Honey Pot Blacklist
	* @param String $access_key Your unique API Access Key provided by Project Honey Pot
	* @return void
	*/
	public function __construct($ip, $access_key) {


		if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			throw new Exception("Provided IP must be in IPv4 notation.");
		}


		$this->ip = $ip;
		$this->access_key = $access_key;
		$this->raw_response = $this->lookup($ip);
		$this->response = explode('.', $this->raw_response);


		if($this->response[0] != 127) {
			throw new Exception("Project Honeypot Lookup for IP $ip Failed. Response was {$this->raw_response}");
		}

		$this->last_activity = (int)$this->response[1];
		$this->threat_score  = (int)$this->response[2];
		$this->visitor_type  = (int)$this->response[3];

	}

	/**
	* Encode an IP Address and Send to Project Honey Pot DNS Network for Response
	*
	* @return String A Project Honey Pot IPv4 like Octet (e.g. 128.0.7.0)
	*/ 
	protected function lookup($ip) {
		
		$reverse_octet = implode('.', array_reverse(explode('.', $ip)));
		$this->search_host = "{$this->access_key}.$reverse_octet." . self::SEARCH_DOMAIN;
		$response = @gethostbyname($this->search_host);

		if($response == $this->search_host) {
			$response = self::NOT_FOUND;
		}

		return $response;
	}

	/**
	* Return the Threat Score: A 0-255 rating of the relative danger posed by the address.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('149.3.139.13', $apikey);
	* 	$result = $h->getThreatScore(); // returns 44; moderately threatening
	* </code>
	*
	* @return int
	*/
	public function getThreatScore() {
		return $this->threat_score;
	}


	/**
	* Return the Project Honey Pot bitset specifying visitor type.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('149.3.139.13', $apikey);
	* 	$result = $h->getVisitorType(); // returns 4; A comment spammer
	* </code>
	*
	* @return int A bitset amalgamating defined visitor types.
	* @see isSuspicious()
	* @see isHarvester()
	* @see isSearchEngine()
	* @see isCommentSpammer()
	*/
	public function getVisitorType() {
		return $this->visitor_type;
	}


	/**
	* Does Project Honey Pot have a record for this IP Address?
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('127.0.0.1', $apikey);
	* 	$result = $h->hasRecord(); // returns FALSE
	* </code>
	*
	* @return bool
	*/
	public function hasRecord() {
		return ($this->raw_response != self::NOT_FOUND) ? true : false;
	}

	/**
	* Is the IP listed as suspicious? IPs with no record return false by default.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('149.3.139.13', $apikey);
	* 	$result = $h->isSuspicious(); // returns true;
	* </code>
	*
	* @return bool
	* @see isHarvester()
	* @see isSearchEngine()
	* @see isCommentSpammer()
	*/
	public function isSuspicious() {

		return ($this->hasRecord() && ($this->getVisitorType() & self::SUSPICIOUS)) ? true : false;
	}


	/**
	* Is the IP listed as a harvester? IPs with no record return false by default.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('149.3.139.13', $apikey);
	* 	$result = $h->isHarvester(); // returns false;
	* </code>
	*
	* @return bool
	* @see isSuspicious()
	* @see isSearchEngine()
	* @see isCommentSpammer()
	*/
	public function isHarvester() {

		return ($this->hasRecord() && ($this->getVisitorType() & self::HARVESTER)) ? true : false;
	}


	/**
	* Is the IP listed as well regarded search engne? IPs with no record return false by default.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('127.0.7.0', $apikey);
	* 	$result = $h->isSearchEngine(); // returns true;
	* </code>
	*
	* @return bool
	* @see isSuspicious()
	* @see isHarvester()
	* @see isCommentSpammer()
	*/
	public function isSearchEngine() {
		return ($this->hasRecord() && ($this->getVisitorType() == self::SEARCH_ENGINE)) ? true : false;
	}


	/**
	* Is the IP listed a known content spammer? IPs with no record return false by default.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('127.0.7.0', $apikey);
	* 	$result = $h->isCommentSpammer(); // returns true;
	* </code>
	*
	* @return bool
	* @see isSuspicious()
	* @see isHarvester()
	* @see isSearchEngine()
	*/
	public function isCommentSpammer() {
		return ($this->hasRecord() && ($this->getVisitorType() & self::COMMENT_SPAMMER)) ? true : false;
	}



	/**
	* Check to see which search engine uses this IP. Returns false if IP 
	* is not associated with a well-regarded search engine.
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('64.233.173.197', $apikey);
	* 	$result = $h->getSearchEngine(); // returns 'Google';
	* </code>
	*
	* @return Mixed 
	* @see isSearchEngine()
	*/
	public function getSearchEngine() {

		if(!$this->isSearchEngine()) {
			return false;
		}

		$engines = 'Undocumented|AltaVista|Ask|Baidu|Excite|Google|Looksmart|Lycos|MSN|Yahoo|Cull|Infoseek|Miscellaneous';
		$engines = explode('|', $engines);


		return $engines[$this->response[2]];

	}

	/**
	* Return the computed hostname used for the Project Honey Pot DNS lookup. 
	* 
	* Example:
	* <code>
	*      
	*   $h = new ProjectHoneyPot('96.47.224.218', $apikey);
	* 	print $h->getSearchHost(); // prints 'nmxyzukokdl.218.224.47.96.dnsbl.httpbl.org';
	* </code>
	*
	* @return String 
	*/
	public function getSearchHost() {
		return $this->search_host;
	}


} // end class

