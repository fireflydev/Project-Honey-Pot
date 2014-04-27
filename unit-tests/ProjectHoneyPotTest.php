<?php

/*
    Tests are based on API test values and expected responses 
    defined at http://www.projecthoneypot.org/httpbl_api.php
*/

class ProjectHoneyPotTest extends PHPUnit_Framework_TestCase {
 



    /**
     * @expectedException Exception
     */
    public function testInvalidInput() {

        $h = new ProjectHoneyPot('Bad Data', PROJECT_HONEY_POT_API_KEY);
    }



    public function testGetThreatScore() {
        
        $h = new ProjectHoneyPot('127.1.80.1', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->getThreatScore(), 80);
    }



    public function testIsSearchEngine() {
        
        $h = new ProjectHoneyPot('127.1.1.0', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->isSearchEngine(), true);
    }



    public function testIsSuspicious() {
        
        $h = new ProjectHoneyPot('127.1.1.1', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->isSuspicious(), true);
    }


    public function testIsHarvester() {
        
        $h = new ProjectHoneyPot('127.1.1.2', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->isHarvester(), true);
    }


    public function testIsCommentSpammer() {
        
        $h = new ProjectHoneyPot('127.1.1.4', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->isCommentSpammer(), true);
    }


    public function testHybridType() {
        
        $h = new ProjectHoneyPot('127.1.1.7', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->isHarvester(), true);
        $this->assertEquals($h->isCommentSpammer(), true);
        $this->assertEquals($h->isSuspicious(), true);
    }


    public function testLastActivity() {
        
        $h = new ProjectHoneyPot('127.20.1.1', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->getLastActivity(), 20);
    }


    public function testIdentifySearchEngine() {
        $h = new ProjectHoneyPot('64.233.173.197', PROJECT_HONEY_POT_API_KEY);
        $this->assertEquals($h->getSearchEngine(), 'Google');
    }



} // end class