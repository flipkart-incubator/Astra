# -*- coding: utf-8 -*-

alerts = [

  {
    'id': 1,
    'name': 'CORS Misconfiguration',
    'Description': 'CORS misconfiguration allows attacker to send a cross domain request and read the response.',
    'remediation': 'Validate origin header and allow only http request from trusted domain'
  },


  {
    'id': 3,
    'name': 'Broken Authentcation and Session Management',
    'Description': 'API is not verifying  authentication for functionality at server side that allows attacker to access unauthorized resource.',
    'remediation': 'Developers frequently build custom authentication and session management schemes, but building these correctly is hard. As a result, these custom schemes frequently have flaws in areas such as logout, password management, timeouts, remember me, secret question, account update, etc. Finding such flaws can sometimes be difficult, as each implementation is unique.'
  },

  {
    'id': 4,
    'name': 'Missing Authentication',
    'Description': 'API does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.',
    'remediation': 'Developers frequently build custom authentication and session management schemes, but building these correctly is hard. As a result, these custom schemes frequently have flaws in areas such as logout, password management, timeouts, remember me, secret question, account update, etc. Finding such flaws can sometimes be difficult, as each implementation is unique.'
  },

  {
    'id': 5,
    'name': 'Session Fixation',
    'Description': "Session Fixation is an attack that permits an attacker to hijack a valid user session. The attack explores a limitation in the way the web application manages the session ID, more specifically the vulnerable web application. When authenticating a user, it doesn’t assign a new session ID, making it possible to use an existent session ID. The attack consists of obtaining a valid session ID (e.g. by connecting to the application), inducing a user to authenticate himself with that session ID, and then hijacking the user-validated session by the knowledge of the used session ID. The attacker has to provide a legitimate Web application session ID and try to make the victim's browser use it.",
    'remediation': 'Simply discarding any existing session is sufficient to force the framework to issue a new sessionid cookie, with a new value.'
  },
  {
      'id': 6,
      'name': 'Cross-Site Request Forgery',
      'Description': "CSRF is an attack that tricks the victim into submitting a malicious request. It inherits the identity and privileges of the victim to perform an undesired function on the victim's behalf. For most sites, browser requests automatically include any credentials associated with the site, such as the user's session cookie, IP address, Windows domain credentials, and so forth. Therefore, if the user is currently authenticated to the site, the site will have no way to distinguish between the forged request sent by the victim and a legitimate request sent by the victim.",
      'remediation': 'The most common method to prevent Cross-Site Request Forgery (CSRF) attacks is to append CSRF tokens to each request and associate them with the user’s session. Such tokens should at a minimum be unique per user session, but can also be unique per request. By including a challenge token with each request, the developer can ensure that the request is valid and not coming from a source other than the user.'
    },

    {
      'id': 7,
      'name': 'Missing Rate limit',
      'Description': 'An attacker can always discover a password through a brute-force attack, but the downside is that it could take years to find it. Depending on the password\'s length and complexity, there could be trillions of possible combinations. To speed things up a bit, a brute-force attack could start with dictionary words or slightly modified dictionary words because most people will use those rather than a completely random password. These attacks are called dictionary attacks or hybrid brute-force attacks. Brute-force attacks put user accounts at risk and flood your site with unnecessary traffic.',
      'remediation': 'The most obvious way to block brute-force attacks is to simply lock out accounts after a defined number of incorrect password attempts. Account lockouts can last a specific duration, such as one hour, or the accounts could remain locked until manually unlocked by an administrator. However, account lockout is not always the best solution, because someone could easily abuse the security measure and lock out hundreds of user accounts'
    }


]
