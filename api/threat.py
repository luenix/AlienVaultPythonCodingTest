"""threat.py
IPDetails data object does the work.  It takes a raw argument, makes
a call to the reputation datastore, and then stores the results in the
data object.  IPDetails does double-duty here as both the plain data
object that can be serialized and the data interface.
"""

import urllib2
import json
import re
import calendar
import time
import collections

# Known bad: 69.43.161.174
# Known good: 8.8.8.8
# Find more examples at https://www.alienvault.com/open-threat-exchange/dashboard


class IPDetails(object):
    """Intended to be called with as_view() through urls.py"""
    def __init__(self, ip=None, *args, **kwargs):
        # ip default value assumed to be "69.43.161.174", a known bad host
        # if ip is None:
        #     ip = "69.43.161.174"

        # TODO: assign values to self
        # default values reflect no Reputation.get_details(self.address) result
        # self.alienvaultid = None

        self.address = ip
        self.id = ""
        self.reputation_val = 0
        self.first_activity = None
        self.last_activity = None
        self.activities = []
        self.activity_types = []
        self.is_valid = False

        # first, check for valid ip address
        #     if valid, set address to validated ip and set is_valid to True
        if ip is not None:
            validated_ip = re.match('^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$', ip)
            if validated_ip is not None:
                self.address = validated_ip.group()
                self.is_valid = True

        reputation_data = Reputation.get_details(self.address)
        reputation = None

        if reputation_data:
            reputation = json.loads(reputation_data)

        if reputation:
            self.id = reputation['_id']['$id']
            self.reputation_val = reputation['reputation_val']

            reputation_activities = reputation['activities']

            # set self.activity_types to set of unique names
            self.activity_types = set([unique_names['name'] for unique_names in reputation_activities])

            # iterate through reputation_activities
            #   set earliest first_activity and latest last_activity values
            #   map reputation_activities to corresponding self.activities list
            for activity in reputation_activities:
                mapped_activity = collections.OrderedDict()

                if 'name' in activity:
                    mapped_activity['activity_type'] = activity['name']

                if 'first_date' in activity:
                    if 'sec' in activity['first_date']:
                        mapped_activity['first_date'] = activity['first_date']['sec']
                        if self.first_activity is None:
                            self.first_activity = mapped_activity['first_date']
                        elif self.first_activity > mapped_activity['first_date']:
                            self.first_activity = mapped_activity['first_date']

                if 'last_date' in activity:
                    if 'sec' in activity['last_date']:
                        mapped_activity['last_date'] = activity['last_date']['sec']
                        if self.last_activity is None:
                            self.last_activity = mapped_activity['last_date']
                        elif self.last_activity < mapped_activity['last_date']:
                            self.last_activity = mapped_activity['last_date']

                if mapped_activity:
                    self.activities.append(mapped_activity)        
        
        return


class Reputation(object):
    @staticmethod
    def get_details(ip=None):
        """If argument ip parses as valid and AV has reputation data for it,
        return raw output of response
        """
        # Added some minor validation to ip argument to allow for
        # possible use of this method outside of IPDetails call
        if ip is not None:
            validated_ip = re.match('^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$', ip)
            if validated_ip:
                try:
                    # TODO: fetch raw results from the source
                    # format: http://reputation.alienvault.com/panel/ip_json.php?ip=69.43.161.174
                    url = "http://reputation.alienvault.com/panel/ip_json.php?ip={!s}".format(validated_ip.group())
                    return urllib2.urlopen(url).read()
                except:
                    return "fetch_error"
        else:
            return None
