<?php
/**
 * SAML 2.0 remote SP metadata for the test IdP (SimpleSAMLphp flatfile).
 *
 * This file registers OUR Service Provider with the test IdP — the same
 * entity id + ACS/SLO the app's SP metadata endpoint (GET /saml/meta, plan
 * 11 S17) publishes. In DFN/GEANT this registration is the operator-submitted
 * registry entry (or the SP metadata document fetched by the federation);
 * here it is a local flatfile so the live SAML dance is reproducible with
 * zero operator action.
 *
 * The compose file bind-mounts this file into
 * /var/www/simplesamlphp/metadata/saml20-sp-remote.php.
 *
 * NOTE: the entity id here (https://smoke.example/saml) is the SP entity id
 * the AuthnRequest carries as <Issuer> AND the audience of the returned
 * assertion (SimpleSAMLphp echoes the registered SP entity into the
 * AudienceRestriction). The harness ssoConfigs row must use the SAME value
 * for `issuer` and `audience`.
 */
$metadata['https://smoke.example/saml'] = array(
    'AssertionConsumerService' => 'https://smoke.example/saml/login/callback',
    'SingleLogoutService' => 'https://smoke.example/saml/logout/callback',
);
