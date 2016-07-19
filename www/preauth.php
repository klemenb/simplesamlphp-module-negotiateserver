<?php

/**
 * This page serves as a placeholder for requesting data from a
 * "HTTP Negotiate" authenticated web page.
 * 
 * @package SimpleSAMLphp
 */

if (!isset($_REQUEST['ReturnTo'])) {
	die('Missing ReturnTo parameter.');
}

if (!isset($_REQUEST['State'])) {
	die('Missing State parameter.');
}

$returnTo = \SimpleSAML\Utils\HTTP::checkURLAllowed($_REQUEST['ReturnTo']);

$authUrl = SimpleSAML\Module::getModuleURL('negotiateserver/auth.php', array(
    'State' => $_REQUEST['State'],
));

$fallbackUrl = SimpleSAML\Module::getModuleURL('negotiateserver/fallback.php', array(
    'State' => $_REQUEST['State'],
));

?>
<!DOCTYPE html>
    <html>
    <head>
        <title>Authentication</title>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <script>
            var request = new XMLHttpRequest();

            request.open("GET", "<?php echo $authUrl ?>", true);

            request.onreadystatechange = function () {
                if (request.readyState !== XMLHttpRequest.DONE) {
                    return;
                }

                if (request.status == 401) {
                    window.location = "<?php echo $fallbackUrl ?>";
                    return;
                }

                window.location = request.response;
            };

            request.send();
        </script>
    </head>
    <body>

    </body>
</html>
