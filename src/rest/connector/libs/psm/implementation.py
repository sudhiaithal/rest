# Global imports
import logging
import time
import requests
import json

# Genie, pyATS, ROBOT imports
# from pyats.connections import BaseConnection
from rest.connector.utils import get_username_password
from rest.connector.implementation import Implementation
from pyats.connections import BaseConnection

# F5 imports
from icontrol.session import iControlRESTSession
from icontrol.exceptions import iControlUnexpectedHTTPError

# create a logger for this module
log = logging.getLogger(__name__)



class Implementation(Implementation):

    """Rest BaseClass



    Baseclass for Rest connection implementation



    YAML Example

    ------------



        devices:

            psm1:
                type: 'generic'
                os: 'psm'
                custom:
                    abstraction:
                        order: [os]
                connections:
                    # Console
                    a:
                        ip: 1.2.3.4
                        port: 22
                        protocol: ssh
                    rest:
                        # specify the rest connector class
                        class: rest.connector.Rest
                        ip: 1.2.3.4
                        port: "443"
                        protocol: https
                        credentials:
                            rest:
                                username: user
                                password: password



    Example

    -------

        >>> from pyats.topology import loader
        >>> testbed = loader.load('/path/to/testbed.yaml')
        >>> device = testbed.devices['psm1']
        >>> device.connect(alias='rest', via='rest')
        >>> device.rest.connected

        True

    """

    @property
    def connected(self):

        """Is a device connected"""

        return self._is_connected

    def disconnect(self):
        '''disconnect the device for this particular alias'''

        log.info("Disconnecting from '{d}' with "
                 "alias '{a}'".format(d=self.device.name, a=self.alias))
        try:
            self.session.close()
        finally:
            self._is_connected = False
        log.info("Disconnected successfully from "
                 "'{d}'".format(d=self.device.name))


    def isconnected(func):
        '''Decorator to make sure the session to device is active.
        If the token experied, it will attempt to reconnect
        '''

        def decorated(self, *args, **kwargs):
            try:
                result = func(self, *args, **kwargs)
            except iControlUnexpectedHTTPError as ex:
                # Auth failure - probably token expired
                if ex.response.status_code == 401:
                    log.info("Session with device %s expired", self.device.name)
                    log.info("Reconnecting to device %s", self.device.name)
                    self._is_connected = False
                    timeout = kwargs['timeout'] if 'timeout' in kwargs else 30
                    self._connect(timeout, retries=0, retry_wait=0)
                    result = func(self, *args, **kwargs)
                else:
                    raise
            return result
        return decorated
    
    @BaseConnection.locked
    def connect(self, timeout=30, port=443, protocol='https', retries=3, retry_wait=10):
        '''connect to the device via REST

        Arguments
        ---------

            timeout (int): Timeout value

            port (int): TCP port to use (default: 443)

            protocol (str): protocol to use (default: https)

            retries (int): Max retries on request exception (default: 3)

            retry_wait (int): Seconds to wait before retry (default: 10)

        Raises
        ------

        Exception
        ---------

            If the connection did not go well

        Note
        ----

        There is no return from this method. If something goes wrong, an
        exception will be raised.


        YAML Example
        ------------

            devices:
                PE1:
                    connections:
                        a:
                            protocol: telnet
                            ip: "1.2.3.4"
                            port: 2004
                        vty:
                            protocol : telnet
                            ip : "2.3.4.5"
                        rest:
                            class: rest.connector.Rest
                            ip : "2.3.4.5"
                            port: "443"
                            protocol: https
                            credentials:
                                rest:
                                    username: admin
                                    password: admin

        Code Example
        ------------

            >>> from pyats.topology import loader
            >>> testbed = loader.load('/users/xxx/xxx/asr22.yaml')
            >>> device = testbed.devices['asr22']
            >>> device.connect(alias='rest', via='rest')
        '''
        if self.connected:
            return


        ip = self.connection_info['ip'].exploded
        port = self.connection_info.get('port', port)
        if 'protocol' in self.connection_info:
            protocol = self.connection_info['protocol']

        self.url = '{protocol}://{ip}:{port}'.format(protocol=protocol,
                                                     ip=ip,
                                                     port=port)

        login_url = '{f}/v1/login'.format(f=self.url)

        username, password = get_username_password(self)

        payload = {
                     "username": username,
                     "password": password,
                     "tenant": "default"            
        }

        log.info("Connecting to '{d}' with alias "
                 "'{a}'".format(d=self.device.name, a=self.alias))

        self.session = requests.Session()

        for _ in range(retries):
            try:
                # Connect to the device via requests
                if protocol == 'https':
                    response = self.session.post(login_url, json=payload, timeout=timeout, verify=False)
                else:
                    response = self.session.post(login_url, json=payload, timeout=timeout)
                break
            except Exception:
                log.warning('Request to {} failed. Waiting {} seconds before retrying\n'.format(
                             self.device.name, retry_wait), exc_info=True)
                time.sleep(retry_wait)
        else:
            raise ConnectionError('Connection to {} failed'.format(self.device.name))

        log.info(response)

        # Make sure it returned requests.codes.ok
        if response.status_code != requests.codes.ok:
            # Something bad happened
            raise RequestException("Connection to '{ip}' has returned the "
                                   "following code '{c}', instead of the "
                                   "expected status code '{ok}'"
                                   .format(ip=ip, c=response.status_code,
                                           ok=requests.codes.ok))

        # Attach auth to session for future calls
        self.session.auth = requests.auth.HTTPBasicAuth(username, password)

        self._is_connected = True
        log.info("Connected successfully to '{d}'".format(d=self.device.name))


    def _connect(self, timeout: int, retries: int, retry_wait: int):
        """ Authenticate and initiate a session with the device

        Args:
            timeout: The timeout to use when establishing the connection
            retries: How many times to retry to connect to the device if it fails
            retry_wait: Time in seconds to wait between retries
        """
        self._authenticate(timeout, retries, retry_wait)

        self._extend_session_ttl(self._ttl)

        params = dict(
            username=self.username,
            password=self.password,
            verify=self.verify,
            token_to_use=self.token
        )

        # creating an object to be used all new requests
        self.icr_session = iControlRESTSession(**params)

        self._is_connected = True

        log.info(
            "Connected successfully to '%s'", self.device.name
        )

    def _authenticate(self, timeout: int, retries: int, retry_wait: int):
        """ Authenticates with the device and retrieves a session token to be
            used in actual requests

        Args:
            timeout: The timeout to use when establishing the connection
            retries: How many times to retry to connect to the device if it fails
            retry_wait: Time in seconds to wait between retries
        """
        # URL to authenticate and receive the token
        url = f"{self.base_url}/mgmt/shared/authn/login"

        payload = {
            'username': self.username,
            'password': self.password,
            'loginProviderName': self._auth_provider
        }

        iCRS = iControlRESTSession(
            self.username,
            self.password,
            timeout=timeout,
            verify=self.verify
        )

        log.info(
            "Connecting to '%s'", self.device.name
        )

        response = iCRS.post(
            url,
            json=payload,
        )

        log.debug(response.json())

        if response.status_code != 200:
            if b'Configuration Utility restarting...' in response.content:
                if retries > 0:
                    time.sleep(retry_wait)
                    return self._authenticate(timeout, retries - 1, retry_wait)
                else:
                    raise iControlUnexpectedHTTPError(
                        f"Failed to connect to {self.device.name}: "
                        f"{response.content}"
                    )
            else:
                raise iControlUnexpectedHTTPError(
                    f"Failed to authenticate with {self.device.name}"
                )

        self.token = response.json()['token']['token']

        log.debug(
            "The following token is used to connect: '%s'", self.token
        )

    def _extend_session_ttl(self, ttl: int) -> None:
        """ Sets the TTL for the active session

        Args:
            ttl: The TTL to be set for the session
        """
        # Self-link of the token
        timeout_url = f"{self.base_url}/mgmt/shared/authz/tokens/{self.token}"
        timeout_payload = {"timeout": ttl}
        token_icr_session = iControlRESTSession(
            self.username,
            self.password,
            verify=self.verify,
            token_to_use=self.token
        )
        # Extending the timeout for the token received
        response = token_icr_session.patch(timeout_url, json=timeout_payload)
        if response.status_code != 200 or not response.ok:
            raise iControlUnexpectedHTTPError(
                "Failed to refresh session: "
                f"{response.reason} ({response.status_code})"
            )
        log.debug("Token TTL extended to '%d' seconds", ttl)

    @isconnected
    def get(self, api_url, timeout=30, verbose=False):

        """GET REST Command to retrieve information from the device"""

        try:
            r = self.session.get(self.url + "/" + api_url, verify=False, timeout=timeout)
            if r.status_code != 200:
                err = f"Get Error {api_url}: [{r.status_code}:{r.reason}] {r.text}"
                raise Exception(err)

            log.debug(
                "Response: {c}, headers: {h}".format(
                    c=r.status_code, h=r.headers
                )
            )
            if verbose:
                log.info("Output received:\n{output}".format(output=r))

            # Make sure it returned ok
            if not r.ok:
                raise Exception(
                    "Connection to '{d}' has returned the "
                    "following code '{c}', instead of the "
                    "expected status code 'ok'".format(
                        d=self.device.name, c=r.status_code
                    )
                )

            log.info(
                "Successfully fetched data from '{d}'".format(d=self.device.name)
            )

            return json.loads(r.content)
                        
        except Exception as e:
            raise Exception("Could not do a get of URL {}".format(api_url))




    @BaseConnection.locked
    @isconnected
    def post(self, api_url, payload, timeout=30, verbose=False):
        """POST REST Command to configure information from the device"""

        try:
            r = self.session.post(self.url + "/" + api_url, json=payload, verify=False, timeout=timeout)
            if r.status_code != 200:
                err = f"Get Error {api_url}: [{r.status_code}:{r.reason}] {r.text}"
                raise Exception(err)

            log.debug(
                "Response: {c}, headers: {h}".format(
                    c=r.status_code, h=r.headers
                )
            )
            if verbose:
                log.info("Output received:\n{output}".format(output=r))

            # Make sure it returned ok
            if not r.ok:
                raise Exception(
                    "Connection to '{d}' has returned the "
                    "following code '{c}', instead of the "
                    "expected status code 'ok'".format(
                        d=self.device.name, c=r.status_code
                    )
                )

            log.info(
                "Successfully posted data to '{d}'".format(d=self.device.name)
            )

            return json.loads(r.content)
                        
        except Exception as e:
            raise Exception("Could not do a post of URL {}".format(api_url))


    @BaseConnection.locked
    @isconnected
    def put(self, api_url, payload, timeout=30, verbose=False):

        """PUT REST Command to update information on the device"""
        try:
            r = self.session.put(self.url + "/" + api_url, json=payload, verify=False, timeout=timeout)
            if r.status_code != 200:
                err = f"Get Error {api_url}: [{r.status_code}:{r.reason}] {r.text}"
                raise Exception(err)

            log.debug(
                "Response: {c}, headers: {h}".format(
                    c=r.status_code, h=r.headers
                )
            )
            if verbose:
                log.info("Output received:\n{output}".format(output=r))

            # Make sure it returned ok
            if not r.ok:
                raise Exception(
                    "Connection to '{d}' has returned the "
                    "following code '{c}', instead of the "
                    "expected status code 'ok'".format(
                        d=self.device.name, c=r.status_code
                    )
                )

            log.info(
                "Successfully put data to '{d}'".format(d=self.device.name)
            )

            return json.loads(r.content)
                        
        except Exception as e:
            raise Exception("Could not do a put of URL {}".format(api_url))
        return output

    @BaseConnection.locked
    @isconnected
    def patch(self, api_url, payload, timeout=30, verbose=False):
        """execute - Not implemented for REST"""

        raise NotImplementedError(
            "execute is not a supported method for REST. "
            "get is probably what you are looking for."
        )


    @BaseConnection.locked
    @isconnected
    def delete(self, api_url, timeout=30, verbose=False):

        """DELETE REST Command to delete information from the device"""

        try:
            r = self.session.delete(self.url + "/" + api_url, verify=False)
            if r.status_code != 200:
                err = f"Get Error {api_url}: [{r.status_code}:{r.reason}] {r.text}"
                raise Exception(err)

            log.debug(
                "Response: {c}, headers: {h}".format(
                    c=r.status_code, h=r.headers
                )
            )
            if verbose:
                log.info("Output received:\n{output}".format(output=r))

            # Make sure it returned ok
            if not r.ok:
                raise Exception(
                    "Connection to '{d}' has returned the "
                    "following code '{c}', instead of the "
                    "expected status code 'ok'".format(
                        d=self.device.name, c=r.status_code
                    )
                )

            log.info(
                "Successfully deleted data to '{d}'".format(d=self.device.name)
            )

            return json.loads(r.content)
                        
        except Exception as e:
            raise Exception("Could not do a delete of URL {}".format(api_url))


    def configure(self, *args, **kwargs):

        """configure - Not implemented for REST"""

        raise NotImplementedError(
            "configure is not a supported method for REST. "
            "post is probably what you are looking for"
        )

    def execute(self, *args, **kwargs):

        """execute - Not implemented for REST"""

        raise NotImplementedError(
            "execute is not a supported method for REST. "
            "get is probably what you are looking for."
        )
