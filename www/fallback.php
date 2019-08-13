<?php

/**
 * This page serves as a fallback page for when "HTTP Negotiate"
 * authentication fails (unsupported, wrong credentials...).
 *
 * @package SimpleSAMLphp
 */

$state = SimpleSAML\Auth\State::loadState($_REQUEST['State'], 'negotiateserver:Negotiate');
SimpleSAML\Logger::debug('Negotiate Server: initiating fallback auth source');

sspmod_negotiateserver_Auth_Source_Negotiate::fallback($state);