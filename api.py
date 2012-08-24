import json
import urllib
import urllib2
import utils


class SCOPES():
    stream = 'stream'
    email = 'email'
    write_post = 'write_post'
    follow = 'follow'
    messages = 'messages'
    export = 'export'


class AppDotNetError(Exception):
    def __init__(self, message, url):
        Exception.__init__(self, message)
        self.url = url


class UserData(object):
    def __init__(self, **kwargs):
        self.id = kwargs['id']
        self.username = kwargs['username']
        self.name = kwargs['name']
        if 'description' in kwargs:
            self.description = Description(**kwargs['description'])
        else:
            self.description = None
        self.timezone = kwargs['timezone']
        self.locale = kwargs['locale']
        self.avatar_image = ImageData(**kwargs['avatar_image'])
        self.cover_image = ImageData(**kwargs['cover_image'])
        self.type = kwargs['type']
        self.created_at = kwargs['created_at']
        self.counts = kwargs['counts']
        # "counts": {
        #     "follows": 100,
        #     "followed_by": 200,
        #     "posts": 24
        # },
        if ('app_data' in kwargs):
            self.app_data = kwargs['app_data']
        # "app_data": {
        #     "appdotnet": {...},
        #     "rdio": {...}
        # },
        if ('follows_you' in kwargs):
            self.follows_you = kwargs['follows_you']
        if ('you_follow' in kwargs):
            self.you_follow = kwargs['you_follow']
        if ('you_muted' in kwargs):
            self.you_muted = kwargs['you_muted']

    def __unicode__(self):
        return u'user @' + self.username + u' [' + self.id + ']'

    def __str__(self):
        return self.__unicode__()


class Description(object):
    def __init__(self, **kwargs):
        self.text = kwargs['text']
        self.html = kwargs['html']
        self.entities = Entities(**kwargs['entities'])


class ImageData(object):
    """
    Represents an AppDotNet image, which consists of height, width, and url.
    """
    def __init__(self, height, width, url):
        self.height = height
        self.width = width
        self.url = url

    @property
    def extension(self):
        return self.url.rsplit('.', 1)[1]

    def get_image(self):
        response = urllib2.urlopen(self.url)
        return response.read()


class Post(object):
    def __init__(self, **kwargs):
        self.id = kwargs['id']
        self.user = None
        if 'user' in kwargs:  # may be omitted (e.g. if the user account has been deleted)
            self.user = UserData(**kwargs['user'])
        self.is_deleted = kwargs.get('is_deleted', False)  # may be omitted if not deleted
        self.created_at = kwargs['created_at']
        self.text = kwargs.get('text', '')  # may be omitted if deleted
        self.html = kwargs.get('html', '')  # may be omitted if deleted
        self.source = Source(**kwargs['source'])
        self.reply_to = kwargs.get('reply_to', None)  # api docs imply that this will always exist but it doesn't
        self.thread_id = kwargs['thread_id']
        self.num_replies = kwargs['num_replies']
        if 'annotations' in kwargs:  # doesn't seem to always exist - maybe not implemented yet
            self.annotations = kwargs['annotations']  # key-value metadata (not well defined yet)
            # "annotations": {
            #     "wellknown:geo": {
            #         "type": "Point",
            #         "coordinates": [102.0, .5]
            #     }
            # },
        if 'entities' in kwargs:  # may be omitted if deleted
            self.entities = Entities(**kwargs['entities'])
        else:
            self.entities = Entities()

    def __unicode__(self):
        return u'Post #' + self.id + u' by: ' + unicode(self.user) + ' -- ' + self.text

    def __str__(self):
        return self.__unicode__()


class Entities(object):
    """ A set of entities """
    def __init__(self, mentions=[], hashtags=[], links=[]):
        self.mentions = self._createEntityList(mentions, MentionEntity)
        self.hashtags = self._createEntityList(hashtags, HashtagEntity)
        self.links = self._createEntityList(links, LinkEntity)

    def _createEntityList(self, provided_data, entity_class):
        entity_list = []
        for entity_data in provided_data:
            entity_list.append(entity_class(**entity_data))


class MentionEntity(object):
    """ A mention type of entity """
    def __init__(self, **kwargs):
        self.name = kwargs['name']
        self.id = kwargs['id']
        self.pos = kwargs['pos']
        self.len = kwargs['len']


class HashtagEntity(object):
    """ A hashtag type of entity """
    def __init__(self, **kwargs):
        self.name = kwargs['name']
        self.pos = kwargs['pos']
        self.len = kwargs['len']


class LinkEntity(object):
    """ A link type of entity """
    def __init__(self, **kwargs):
        self.text = kwargs['text']
        self.url = kwargs['url']
        self.pos = kwargs['pos']
        self.len = kwargs['len']

    @property
    def json(self):
        d = {'text': self.text,
             'url': self.url,
             'pos': self.pos,
             'len': self.len}
        return json.dumps(d)


class Filter(object):
    """ A whitelist or blacklist for a post stream. """
    def __init__(self, **kwargs):
        # The example in the api shows an id field but the description doesn't mention it.
        if 'id' in kwargs:
            self.id = kwargs['id']
        self.type = kwargs['type']
        # Check that it's a valid type
        if self.type not in ['show', 'block']:
            raise AppDotNetError("Unrecognized filter type :%s" % self.type, None)
        self.name = kwargs['name']
        self.user_ids = kwargs['user_ids']
        self.hashtags = kwargs['hashtags']
        self.link_domains = kwargs['link_domains']
        self.mention_user_ids = kwargs['mention_user_ids']


class Source(object):
    def __init__(self, name, link):
        self.name = name
        self.link = link


class AppDotNet(object):
    """docstring for AppDotNet"""
    def __init__(self, client_id=None, client_secret=None, scopes=None, access_token=None):
        super(AppDotNet, self).__init__()
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.requested_scopes = scopes
        self.user = None
        self.scopes = []
        if self.access_token:
            self.verify_token()

    def make_authorized_request(self, url, post_data=None, method=None):
        response_data = None
        headers = {'Authorization': 'Bearer ' + self.access_token}
        request = utils.RequestWithMethod(url=url, headers=headers, data=post_data, method=method)
        try:
            response = urllib2.urlopen(request)
            response_body = response.read()
            response_data = json.loads(response_body)
        except urllib2.HTTPError, e:
            error_url = e.geturl()
            if e.code == 404:
                error_message = '404: File not found.'
            else:
                error_message = json.loads(e.read())['error']
            raise AppDotNetError(error_message, error_url)
        return response_data

    def verify_token(self):
        url = "https://alpha-api.app.net/stream/0/token"
        data = self.make_authorized_request(url)
        self.scopes = data['scopes']
        self.user = UserData(**data['user'])

    def has_all_requested_scopes(self):
        return_value = True
        for s in self.requested_scopes:
            if s not in self.scopes:
                return_value = False
        return return_value

    def is_authenticated(self):
        return self.access_token != None

    def authentication_url(self):
        scopes = ''
        for scope in self.requested_scopes:
            scopes += scope + ' '
        url = 'https://alpha.app.net/oauth/authenticate'
        url += '?client_id=' + self.client_id
        url += '&response_type=code'
        # url += '&redirect_uri=[your redirect URI]'
        url += '&scope=' + scopes
        return url

    def retrieve_access_token(self, auth_code):
        """
        If you get an 'Invalid Token' error that means that the code provided didn't
        work. This can happen if it is incorrect or has already been used.
        'code must be specified for grant type authorization_code' means that you didn't
        provide a code.
        """
        request = utils.RequestWithMethod(url='https://alpha.app.net/oauth/access_token',
                                          data=urllib.urlencode({
                                            'client_id': self.client_id,
                                            'client_secret': self.client_secret,
                                            'grant_type': 'authorization_code',
                                            # 'redirect_uri': 'http://branhandley.com',
                                            'code': auth_code}))
        try:
            response = urllib2.urlopen(request)
            response_data = json.loads(response.read())
            self.access_token = response_data['access_token']
            self.verify_token()  # Verify the token to get user and scope information
        except urllib2.HTTPError, e:
            error_url = e.geturl()
            error_message = json.loads(e.read())['error']
            raise AppDotNetError(error_message, error_url)
        return self.access_token

    def get_user(self, user_id):
        """
        user_id can be:
            - the actual id of the user
            - 'me' for the currently authenticated user
            - '@username' of the user
        """
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id
        return UserData(**self.make_authorized_request(url=url))

    def follow_user(self, user_id=None, user=None):
        if user_id == None:
            user_id = user.id
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/follow'
        return UserData(**self.make_authorized_request(url=url, method="POST"))

    def unfollow_user(self, user_id=None, user=None):
        if user_id == None:
            user_id = user.id
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/follow'
        return UserData(**self.make_authorized_request(url=url, method="DELETE"))

    def followed_by_user(self, user_id=None, user=None):
        if user_id == None:
            user_id = user.id
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/following'
        return [UserData(**user_data) for user_data in self.make_authorized_request(url=url)]

    def followers_of_user(self, user_id=None, user=None):
        if user_id == None:
            user_id = user.id
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/followers'
        return [UserData(**user_data) for user_data in self.make_authorized_request(url=url)]

    def mute_user(self, user_id=None, user=None):
        if user_id == None:
            user_id = user.id
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/mute'
        return UserData(**self.make_authorized_request(url=url, method="POST"))

    def unmute_user(self, user_id=None, user=None):
        if user_id == None:
            user_id = user.id
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/mute'
        return UserData(**self.make_authorized_request(url=url, method="DELETE"))

    def my_muted_users(self):
        """ Can only see current users muted users """
        url = 'https://alpha-api.app.net/stream/0/users/me/muted'
        return [UserData(**user_data) for user_data in self.make_authorized_request(url=url)]

    def get_post(self, post_id):
        """ Retrieve the specified post """
        # seems that post_id has to > 0
        url = 'https://alpha-api.app.net/stream/0/posts/' + post_id
        return Post(**self.make_authorized_request(url=url))

    def get_post_replies(self, post_id, since_id=None, before_id=None, count=None, include_user=None, include_annotations=None, include_replies=None):
        """ Retrieve the replies to a post """
        parameters = {'since_id': since_id, 'before_id': before_id, 'count': count, 'include_user': include_user, 'include_annotations': include_annotations, 'include_replies': include_replies}
        for key, value in parameters.items():
            if value == None:
                del parameters[key]
        query_string = ''
        if parameters.keys():
            query_string = '?' + urllib.urlencode(parameters)
        url = 'https://alpha-api.app.net/stream/0/posts/' + post_id + '/replies' + query_string
        return [Post(**post_data) for post_data in self.make_authorized_request(url=url)]

    def get_user_posts(self, user_id, since_id=None, before_id=None, count=None, include_user=None, include_annotations=None, include_replies=None):
        """ Retrieve the user's posts. """
        parameters = {'since_id': since_id, 'before_id': before_id, 'count': count, 'include_user': include_user, 'include_annotations': include_annotations, 'include_replies': include_replies}
        for key, value in parameters.items():
            if value == None:
                del parameters[key]
        query_string = ''
        if parameters.keys():
            query_string = '?' + urllib.urlencode(parameters)
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/posts' + query_string
        return [Post(**post_data) for post_data in self.make_authorized_request(url=url)]

    def get_user_mentions(self, user_id, since_id=None, before_id=None, count=None, include_user=None, include_annotations=None, include_replies=None):
        """ Retrieve the posts mentioning the user. """
        parameters = {'since_id': since_id, 'before_id': before_id, 'count': count, 'include_user': include_user, 'include_annotations': include_annotations, 'include_replies': include_replies}
        for key, value in parameters.items():
            if value == None:
                del parameters[key]
        query_string = ''
        if parameters.keys():
            query_string = '?' + urllib.urlencode(parameters)
        url = 'https://alpha-api.app.net/stream/0/users/' + user_id + '/mentions' + query_string
        return [Post(**post_data) for post_data in self.make_authorized_request(url=url)]

    def get_my_stream(self, since_id=None, before_id=None, count=None, include_user=None, include_annotations=None, include_replies=None):
        """
        Retrieve the user's stream.
        These are the latest posts by the current user and the users they follow.

        NEEDS stream scope
        """
        parameters = {'since_id': since_id, 'before_id': before_id, 'count': count, 'include_user': include_user, 'include_annotations': include_annotations, 'include_replies': include_replies}
        for key, value in parameters.items():
            if value == None:
                del parameters[key]
        query_string = ''
        if parameters.keys():
            query_string = '?' + urllib.urlencode(parameters)
        url = 'https://alpha-api.app.net/stream/0/posts/stream' + query_string
        return [Post(**post_data) for post_data in self.make_authorized_request(url=url)]

    def get_global_stream(self, since_id=None, before_id=None, count=None, include_user=None, include_annotations=None, include_replies=None):
        """
        Retrieve the global stream.
        These are the latest posts amongst all users.
        """
        parameters = {'since_id': since_id, 'before_id': before_id, 'count': count, 'include_user': include_user, 'include_annotations': include_annotations, 'include_replies': include_replies}
        for key, value in parameters.items():
            if value == None:
                del parameters[key]
        query_string = ''
        if parameters.keys():
            query_string = '?' + urllib.urlencode(parameters)
        url = 'https://alpha-api.app.net/stream/0/posts/stream/global' + query_string
        return [Post(**post_data) for post_data in self.make_authorized_request(url=url)]

    def get_tagged_posts(self, hashtag, since_id=None, before_id=None, count=None, include_user=None, include_annotations=None, include_replies=None):
        """
        Retrieve recent posts with the specified hashtag.
        """
        parameters = {'since_id': since_id, 'before_id': before_id, 'count': count, 'include_user': include_user, 'include_annotations': include_annotations, 'include_replies': include_replies}
        for key, value in parameters.items():
            if value == None:
                del parameters[key]
        query_string = ''
        if parameters.keys():
            query_string = '?' + urllib.urlencode(parameters)
        url = 'https://alpha-api.app.net/stream/0/posts/tag/' + hashtag + query_string
        return [Post(**post_data) for post_data in self.make_authorized_request(url=url)]

    def new_post(self, text, in_reply_to=None, links=None):
        """
        Submits a new post by the current user.
        The entities may contain links and annotations (not supported yet).
        Any mentions in the entities will be ignored.

        NEEDS write_post scope
        """
        post_data = {'text': text, 'reply_to': in_reply_to}
#        post_data = {'text': text, 'reply_to': in_reply_to, 'links': '{"url": "http://google.com", "text": "This", "pos": 1, "len": 4}'}
        # Convert link objects to json
        # links_json = []
        # for link in links:
        #     links_json.append(link.json)
        # if links_json:
        #     post_data['links'] = links_json
        post_data = urllib.urlencode(post_data)
        url = 'https://alpha-api.app.net/stream/0/posts'
        return Post(**self.make_authorized_request(url=url, post_data=post_data, method="POST"))

    def delete_post(self, post_id):
        url = 'https://alpha-api.app.net/stream/0/posts/' + post_id
        return Post(**self.make_authorized_request(url=url, method="DELETE"))
