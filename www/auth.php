<?php

/**
 * This page serves as a "HTTP Negotiate" authenticated web page
 * where web server provides the necessary user information. It
 * outputs the URL for the next step of the authentication flow.
 *
 * @package SimpleSAMLphp
 */

if (!isset($_REQUEST['State'])) {
    die('Missing State parameter.');
}

$state = SimpleSAML\Auth\State::loadState($_REQUEST['State'], 'negotiateserver:Negotiate');

if (!empty($_SERVER['REMOTE_USER'])) {
    $state['UserIdentifier'] = $_SERVER['REMOTE_USER'];
}

$stateId = SimpleSAML\Auth\State::saveState($state, 'negotiateserver:Negotiate');

echo SimpleSAML\Module::getModuleURL('negotiateserver/resume.php', array(
    'State' => $stateId,
));
