<?php

/**
 * The "Negotiate Server" module. Allows for passwordless, secure login via HTTP Negotiate
 * by offloading authentication processing to the web server.
 *
 * @author Klemen Bratec <klemen.bratec@gmail.com>
 * @package SimpleSAMLphp
 */
class sspmod_negotiateserver_Auth_Source_Negotiate extends SimpleSAML\Auth\Source
{
    protected $ldap;

    protected $ldap_hostname;
    protected $ldap_port;
    protected $ldap_timeout;
    protected $ldap_referrals;
    protected $ldap_enableTLS;
    protected $ldap_debug;
    protected $ldap_base;
    protected $ldap_admin_user;
    protected $ldap_admin_password;
    protected $ldap_identifier;

    protected $subnets;
    protected $subnets_exclude;
    protected $attributes;
    protected $auth_fallback;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config The configuration of the module
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        parent::__construct($info, $config);

        $config = SimpleSAML\Configuration::loadFromArray($config);

        $this->ldap_hostname = $config->getArrayize('ldap.hostname');
        $this->ldap_port = $config->getString('ldap.port', 389);
        $this->ldap_timeout = $config->getString('ldap.timeout', 10);
        $this->ldap_enableTLS = $config->getBoolean('ldap.enableTLS', false);
        $this->ldap_debug = $config->getBoolean('ldap.debug', false);
        $this->ldap_referrals = $config->getBoolean('ldap.referrals', true);
        $this->ldap_admin_user = $config->getString('ldap.admin_user', null);
        $this->ldap_admin_password = $config->getString('ldap.admin_password', null);
        $this->ldap_base = $config->getArrayizeString('ldap.base');
        $this->ldap_identifier = $config->getString('ldap.identifier');

        $this->attributes = $config->getArrayizeString('attributes', null);
        $this->subnets = $config->getArrayizeString('subnets', null);
        $this->subnets_exclude = $config->getArrayizeString('subnets_exclude', null);
        $this->auth_fallback = $config->getString('auth_fallback');
    }

    /**
     * The inner workings of the module. Check client's subnet and redirect
     * to an authentication page protected with "HTTP Negotiate" authentication
     * or a fallback authentication source.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('is_array($state)');

        $state['negotiateserver:AuthID'] = $this->authId;
        $state['negotiateserver:AuthFallback'] = $this->auth_fallback;

        if (!$this->checkClientSubnet()) {
            $this->fallback($state);
        }

        $stateId = SimpleSAML\Auth\State::saveState($state, 'negotiateserver:Negotiate');

        $returnTo = SimpleSAML\Module::getModuleURL('negotiateserver/resume.php', array(
            'State' => $stateId,
        ));

        $authPage = SimpleSAML\Module::getModuleURL('negotiateserver/preauth.php');

        \SimpleSAML\Utils\HTTP::redirectTrustedURL($authPage, array(
            'State' => $stateId,
            'ReturnTo' => $returnTo,
        ));

        assert('FALSE');
    }

    public static function resume()
    {
        if (!isset($_REQUEST['State'])) {
            throw new SimpleSAML\Error\BadRequest('Missing "State" parameter.');
        }

        $state = SimpleSAML\Auth\State::loadState($_REQUEST['State'], 'negotiateserver:Negotiate');

        $source = SimpleSAML\Auth\Source::getById($state['negotiateserver:AuthID']);

        if ($source === NULL) {
            throw new SimpleSAML\Error\Exception('Could not find authentication source with id '
                . $state[self::authId]);
        }

        if (!($source instanceof self)) {
            throw new SimpleSAML\Error\Exception('Authentication source type changed.');
        }

        if (empty($state['UserIdentifier'])) {
            throw new SimpleSAML\Error\Exception('User identifier is empty or not set.');
        }

        $attributes = $source->getUserAttributes($state['UserIdentifier']);

        if ($attributes === NULL) {
            throw new SimpleSAML\Error\Exception('User not authenticated after login page.');
        }

        $state['Attributes'] = $attributes;

        SimpleSAML\Auth\Source::completeAuth($state);

        assert('FALSE');
    }

    private function getUserAttributes($identifier)
    {
        $parts = explode('@', $identifier);
        $domain = '';

        // remove $realm from identifier and save into $domain
        if (count($parts) > 1) {
            $identifier = $parts[0];
            $domain = $parts[1];
        } else {
            $parts = explode('\\', $identifier);

            if (count($parts) > 1) {
                $identifier = $parts[1];
                $domain = $parts[0];
            }
        }

        $this->ldap = new SimpleSAML\Auth\LDAP(
            array_key_exists($domain, $this->ldap_hostname) ? $this->ldap_hostname["${domain}"] : $this->ldap_hostname[0],
            $this->ldap_enableTLS,
            $this->ldap_debug,
            $this->ldap_timeout,
            $this->ldap_port,
            $this->ldap_referrals
        );

        $this->bindLdapAdmin();

        $dn = $this->ldap->searchfordn(
            array_key_exists($domain, $this->ldap_base) ? $this->ldap_base["${domain}"] : $this->ldap_base,
            $this->ldap_identifier,
            $identifier
        );

        return $this->ldap->getAttributes($dn, $this->attributes);
    }

    protected function bindLdapAdmin()
    {
        if ($this->ldap_admin_user === null) {
            return;
        }

        if (!$this->ldap->bind($this->ldap_admin_user, $this->ldap_admin_password)) {
            throw new SimpleSAML\Error\Exception('LDAP admin bind failed.');
        }
    }

    public function checkClientSubnet()
    {
        // Accept all clients when no subnets are configured
        if (empty($this->subnets) && empty($this->subnets_exclude)) {
            return true;
        }

        $ip = $_SERVER['REMOTE_ADDR'];

        // "Allow by default" when only exclusion subnets are configured
        if (empty($this->subnets) && !empty($this->subnets_exclude)) {
            $allow = true;
        } else {
            $allow = false;
        }

        // Check if client's IP address belongs to an allowed subnet
        if ($this->subnets != null) {
            foreach ($this->subnets as $cidr) {
                if (SimpleSAML\Utils\Net::ipCIDRcheck($cidr)) {
                    SimpleSAML\Logger::debug('Negotiate Server: Client "' . $ip . '" matched allowed subnet "' . $cidr .'".');
                    $allow = true;
                }
            }

            if (!$allow) {
                SimpleSAML\Logger::debug('Negotiate Server: Client "' . $ip . '" did not match an allowed subnet.');
            }
        }

        // Check if client's IP address belongs to an excluded subnet
        if ($this->subnets_exclude != null) {
            foreach ($this->subnets_exclude as $cidr) {
                if (SimpleSAML\Utils\Net::ipCIDRcheck($cidr)) {
                    SimpleSAML\Logger::debug('Negotiate Server: Client "' . $ip . '" matched excluded subnet "' . $cidr . '".');
                    $allow = false;
                }
            }

            if ($allow) {
                SimpleSAML\Logger::debug('Negotiate Server: Client "' . $ip . '" did not match an excluded subnet.');
            }
        }

        return $allow;
    }

    public static function fallback(&$state)
    {
        $authId = $state['negotiateserver:AuthFallback'];

        if ($authId === null) {
            throw new SimpleSAML\Error\Error(500, "Unable to determine fallback auth source.");
        }

        $source = SimpleSAML\Auth\Source::getById($authId);

        try {
            $source->authenticate($state);
        } catch (SimpleSAML\Error\Exception $e) {
            SimpleSAML\Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new SimpleSAML\Error\UnserializableException($e);
            SimpleSAML\Auth\State::throwException($state, $e);
        }

        SimpleSAML\Logger::debug('Negotiate Server: fallback auth source returned');

        self::loginCompleted($state);
    }
}
