import re

from array import array
from java.io import PrintWriter
from burp import (
    IBurpExtender,
    IScanIssue,
    IScannerCheck,
)

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class EnumMeta(type):
    def __iter__(cls):
        return iter(
            [
                getattr(cls, attr)
                for attr in dir(cls)
                if not callable(getattr(cls, attr)) and not attr.startswith("__")
            ]
        )

    def __contains__(cls, value):
        return any(value == item for item in cls.__dict__.values())


class Severity:
    __metaclass__ = EnumMeta
    HIGH = 10
    SYNTAX = 20
    MEDIUM = 30
    HIGH_MAYBE = 40
    STRICT_CSP = 45
    MEDIUM_MAYBE = 50
    INFO = 60
    NONE = 100


class FindingType:
    __metaclass__ = EnumMeta

    # Parser checks
    MISSING_SEMICOLON = 100
    UNKNOWN_DIRECTIVE = 101
    INVALID_KEYWORD = 102
    NONCE_CHARSET = 106

    # Security checks
    MISSING_DIRECTIVES = 300
    SCRIPT_UNSAFE_INLINE = 301
    SCRIPT_UNSAFE_EVAL = 302
    PLAIN_URL_SCHEMES = 303
    PLAIN_WILDCARD = 304
    SCRIPT_ALLOWLIST_BYPASS = 305
    OBJECT_ALLOWLIST_BYPASS = 306
    NONCE_LENGTH = 307
    IP_SOURCE = 308
    DEPRECATED_DIRECTIVE = 309
    SRC_HTTP = 310

    # Strict dynamic and backward compatibility checks
    STRICT_DYNAMIC = 400
    STRICT_DYNAMIC_NOT_STANDALONE = 401
    NONCE_HASH = 402
    UNSAFE_INLINE_FALLBACK = 403
    ALLOWLIST_FALLBACK = 404
    IGNORED = 405

    # Trusted Types checks
    REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS = 500

    # Lighthouse checks
    REPORTING_DESTINATION_MISSING = 600
    REPORT_TO_ONLY = 601


class Finding:
    def __init__(
        self,
        finding_type,
        description,
        severity,
        directive,
        value=None,
    ):
        self.type = finding_type
        self.description = description
        self.severity = severity
        self.directive = directive
        self.value = value

    def __eq__(self, obj):
        if not isinstance(obj, Finding):
            return False
        return (
            obj.type == self.type
            and obj.description == self.description
            and obj.severity == self.severity
            and obj.directive == self.directive
            and obj.value == self.value
        )

    @staticmethod
    def get_highest_severity(findings):
        if not findings:
            return None
        severities = [finding.severity for finding in findings]
        return min(severities)


class TrustedTypesSink:
    __metaclass__ = EnumMeta
    SCRIPT = "'script'"


class Keyword:
    __metaclass__ = EnumMeta
    SELF = "'self'"
    NONE = "'none'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    WASM_EVAL = "'wasm-eval'"
    WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    UNSAFE_HASHED_ATTRIBUTES = "'unsafe-hashed-attributes'"
    UNSAFE_HASHES = "'unsafe-hashes'"
    REPORT_SAMPLE = "'report-sample'"
    BLOCK = "'block'"
    ALLOW = "'allow'"


class Directive:
    __metaclass__ = EnumMeta
    # Fetch directives
    CHILD_SRC = "child-src"
    CONNECT_SRC = "connect-src"
    DEFAULT_SRC = "default-src"
    FONT_SRC = "font-src"
    FRAME_SRC = "frame-src"
    IMG_SRC = "img-src"
    MEDIA_SRC = "media-src"
    OBJECT_SRC = "object-src"
    SCRIPT_SRC = "script-src"
    SCRIPT_SRC_ATTR = "script-src-attr"
    SCRIPT_SRC_ELEM = "script-src-elem"
    STYLE_SRC = "style-src"
    STYLE_SRC_ATTR = "style-src-attr"
    STYLE_SRC_ELEM = "style-src-elem"
    PREFETCH_SRC = "prefetch-src"

    MANIFEST_SRC = "manifest-src"
    WORKER_SRC = "worker-src"

    # Document directives
    BASE_URI = "base-uri"
    PLUGIN_TYPES = "plugin-types"
    SANDBOX = "sandbox"
    DISOWN_OPENER = "disown-opener"

    # Navigation directives
    FORM_ACTION = "form-action"
    FRAME_ANCESTORS = "frame-ancestors"
    NAVIGATE_TO = "navigate-to"

    # Reporting directives
    REPORT_TO = "report-to"
    REPORT_URI = "report-uri"

    # Other directives
    BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content"
    UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"
    REFLECTED_XSS = "reflected-xss"
    REFERRER = "referrer"
    REQUIRE_SRI_FOR = "require-sri-for"
    TRUSTED_TYPES = "trusted-types"

    # https:#github.com/WICG/trusted-types
    REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for"
    WEBRTC = "webrtc"


class Version:
    __metaclass__ = EnumMeta
    CSP1 = 1
    CSP2 = 2
    CSP3 = 3


class CSP:
    directives = None

    def __init__(self):
        self.directives = {}

    def clone(self):
        clone = CSP()
        for directive, directiveValues in self.directives.items():
            if directiveValues:
                clone.directives[directive] = directiveValues[:]
        return clone

    def convert_to_string(self):
        csp_string = ""
        for directive, directive_values in self.directives.items():
            csp_string += directive
            if directive_values is not None:
                for value in directive_values:
                    csp_string += " "
                    csp_string += value
            csp_string += "; "
        return csp_string

    FETCH_DIRECTIVES = [
        Directive.CHILD_SRC,
        Directive.CONNECT_SRC,
        Directive.DEFAULT_SRC,
        Directive.FONT_SRC,
        Directive.FRAME_SRC,
        Directive.IMG_SRC,
        Directive.MANIFEST_SRC,
        Directive.MEDIA_SRC,
        Directive.OBJECT_SRC,
        Directive.SCRIPT_SRC,
        Directive.SCRIPT_SRC_ATTR,
        Directive.SCRIPT_SRC_ELEM,
        Directive.STYLE_SRC,
        Directive.STYLE_SRC_ATTR,
        Directive.STYLE_SRC_ELEM,
        Directive.WORKER_SRC,
    ]

    STRICT_NONCE_PATTERN = r"^'nonce-[a-zA-Z0-9+/_-]+[=]{0,2}'$"

    NONCE_PATTERN = r"^'nonce-(.+)'$"

    @staticmethod
    def is_nonce(nonce, strict_check=True):
        pattern = CSP.STRICT_NONCE_PATTERN if strict_check else CSP.NONCE_PATTERN
        return re.match(pattern, nonce)

    @staticmethod
    def is_url_scheme(url_scheme):
        pattern = r"^[a-zA-Z][+a-zA-Z0-9.-]*:$"
        return re.match(pattern, url_scheme)

    @staticmethod
    def is_keyword(keyword):
        return keyword in [e for e in Keyword]

    @staticmethod
    def is_directive(directive):
        return directive in [e for e in Directive]

    STRICT_HASH_PATTERN = r"^'(sha256|sha384|sha512)-[a-zA-Z0-9+/]+[=]{0,2}'$"

    # A regex pattern to check hash prefix.
    HASH_PATTERN = r"^'(sha256|sha384|sha512)-(.+)'$"

    @staticmethod
    def is_hash(hash, strict_check=True):
        pattern = CSP.STRICT_HASH_PATTERN if strict_check else CSP.HASH_PATTERN
        return re.match(pattern, hash)

    def get_effective_directive(self, directive):
        # Only fetch directives default to default-src.
        if directive not in self.directives and directive in self.FETCH_DIRECTIVES:
            return Directive.DEFAULT_SRC
        return directive

    def get_effective_directives(self, directives):
        effective_directives = set(
            [self.get_effective_directive(directive) for directive in directives]
        )
        return list(effective_directives)

    def policy_has_script_nonces(self):
        directive_name = self.get_effective_directive(Directive.SCRIPT_SRC)
        values = self.directives.get(directive_name, [])
        return any(self.is_nonce(val) for val in values)

    def policy_has_script_hashes(self):
        directive_name = self.get_effective_directive(Directive.SCRIPT_SRC)
        values = self.directives.get(directive_name, [])
        return any(self.is_hash(val) for val in values)

    def policy_has_strict_dynamic(self):
        directive_name = self.get_effective_directive(Directive.SCRIPT_SRC)
        values = self.directives.get(directive_name, [])
        return Keyword.STRICT_DYNAMIC in values

    def get_effective_csp(self, csp_version, opt_findings=None):
        findings = opt_findings or []
        effective_csp = self.clone()
        directive = effective_csp.get_effective_directive(Directive.SCRIPT_SRC)
        values = self.directives.get(directive, [])
        effective_csp_values = effective_csp.directives.get(directive, None)

        if effective_csp_values and (
            effective_csp.policy_has_script_nonces()
            or effective_csp.policy_has_script_hashes()
        ):
            if csp_version >= Version.CSP2:
                # Ignore 'unsafe-inline' in CSP >= v2, if a nonce or a hash is present.
                if Keyword.UNSAFE_INLINE in values:
                    effective_csp_values.remove(Keyword.UNSAFE_INLINE)
                    findings.append(
                        Finding(
                            FindingType.IGNORED,
                            "unsafe-inline is ignored if a nonce or a hash is present. (CSP2 and above)",
                            Severity.NONE,
                            directive,
                            Keyword.UNSAFE_INLINE,
                        )
                    )
            else:
                # remove nonces and hashes (not supported in CSP < v2).
                for value in values:
                    if value.startswith("'nonce-") or value.startswith("'sha"):
                        effective_csp_values.remove(value)

        if effective_csp_values and self.policy_has_strict_dynamic():
            # Ignore allowlist in CSP >= v3 in presence of 'strict-dynamic'.
            if csp_version >= Version.CSP3:
                for value in values:
                    # Because of 'strict-dynamic' all host-source and scheme-source
                    # expressions, as well as the "'unsafe-inline'" and "'self'
                    # keyword-sources will be ignored.
                    # https://w3c.github.io/webappsec-csp/#strict-dynamic-usage
                    if (
                        not value.startswith("'")
                        or value == Keyword.SELF
                        or value == Keyword.UNSAFE_INLINE
                    ):
                        try:
                            effective_csp_values.remove(value)
                        except ValueError:
                            # Value may not be in the list
                            pass
                        findings.append(
                            Finding(
                                FindingType.IGNORED,
                                "Because of strict-dynamic this entry is ignored in CSP3 and above",
                                Severity.NONE,
                                directive,
                                value,
                            )
                        )
            else:
                # strict-dynamic not supported.
                effective_csp_values.remove(Keyword.STRICT_DYNAMIC)

        if csp_version < Version.CSP3:
            # Remove CSP3 directives from pre-CSP3 policies.
            # https://w3c.github.io/webappsec-csp/#changes-from-level-2
            effective_csp.directives.pop(Directive.REPORT_TO, None)
            effective_csp.directives.pop(Directive.WORKER_SRC, None)
            effective_csp.directives.pop(Directive.MANIFEST_SRC, None)
            effective_csp.directives.pop(Directive.TRUSTED_TYPES, None)
            effective_csp.directives.pop(Directive.REQUIRE_TRUSTED_TYPES_FOR, None)

        return effective_csp


def check_unknown_directive(parsed_csp):
    findings = []

    for directive in parsed_csp.directives.keys():
        if CSP.is_directive(directive):
            # Directive is known.
            continue

        if directive.endswith(":"):
            findings.append(
                Finding(
                    FindingType.UNKNOWN_DIRECTIVE,
                    "CSP directives don't end with a colon.",
                    Severity.SYNTAX,
                    directive,
                )
            )
        else:
            findings.append(
                Finding(
                    FindingType.UNKNOWN_DIRECTIVE,
                    "Directive " + directive + " is not a known CSP directive.",
                    Severity.SYNTAX,
                    directive,
                )
            )

    return findings


def check_missing_semicolon(parsed_csp):
    findings = []

    for directive, directiveValues in parsed_csp.directives.items():
        if directiveValues is None:
            continue
        for value in directiveValues:
            # If we find a known directive inside a directive value, it is very
            # likely that a semicolon was forgoten.
            if CSP.is_directive(value):
                findings.append(
                    Finding(
                        FindingType.MISSING_SEMICOLON,
                        "Did you forget the semicolon? "
                        + value
                        + " seems to be a directive, not a value.",
                        Severity.SYNTAX,
                        directive,
                        value,
                    )
                )

    return findings


def check_invalid_keyword(parsed_csp):
    findings = []
    keywords_no_ticks = [k.replace("'", "") for k in [l for l in Keyword]]

    for directive, directive_values in parsed_csp.directives.items():
        if directive_values is None:
            continue
        for value in directive_values:
            # Check if single ticks have been forgotten.
            if (
                any(k == value for k in keywords_no_ticks)
                or value.startswith("nonce-")
                or re.match("^(sha256|sha384|sha512)-", value)
            ):
                findings.append(
                    Finding(
                        FindingType.INVALID_KEYWORD,
                        "Did you forget to surround + " + value + " with single-ticks?",
                        Severity.SYNTAX,
                        directive,
                        value,
                    )
                )
                continue

            # Continue, if the value doesn't start with single tick.
            # All CSP keywords start with a single tick.
            if not value.startswith("'"):
                continue

            if directive == Directive.REQUIRE_TRUSTED_TYPES_FOR:
                # Continue, if it's an allowed Trusted Types sink.
                if value == TrustedTypesSink.SCRIPT:
                    continue
            elif directive == Directive.TRUSTED_TYPES:
                # Continue, if it's an allowed Trusted Types keyword.
                if value == "'allow-duplicates'" or value == "'none'":
                    continue
            else:
                # Continue, if it's a valid keyword.
                if CSP.is_keyword(value) or CSP.is_hash(value) or CSP.is_nonce(value):
                    continue

            findings.append(
                Finding(
                    FindingType.INVALID_KEYWORD,
                    value + " seems to be an invalid CSP keyword.",
                    Severity.SYNTAX,
                    directive,
                    value,
                )
            )

    return findings


JSONP_NEEDS_EVAL = [
    "googletagmanager.com",
    "www.googletagmanager.com",
    "www.googleadservices.com",
    "google-analytics.com",
    "ssl.google-analytics.com",
    "www.google-analytics.com",
]

JSONP_URLS = [
    "//bebezoo.1688.com/fragment/index.htm",
    "//www.google-analytics.com/gtm/js",
    "//googleads.g.doubleclick.net/pagead/conversion/1036918760/wcm",
    "//www.googleadservices.com/pagead/conversion/1070110417/wcm",
    "//www.google.com/tools/feedback/escalation-options",
    "//pin.aliyun.com/check_audio",
    "//offer.alibaba.com/market/CID100002954/5/fetchKeyword.do",
    "//ccrprod.alipay.com/ccr/arriveTime.json",
    "//group.aliexpress.com/ajaxAcquireGroupbuyProduct.do",
    "//detector.alicdn.com/2.7.3/index.php",
    "//suggest.taobao.com/sug",
    "//translate.google.com/translate_a/l",
    "//count.tbcdn.cn//counter3",
    "//wb.amap.com/channel.php",
    "//translate.googleapis.com/translate_a/l",
    "//afpeng.alimama.com/ex",
    "//accounts.google.com/o/oauth2/revoke",
    "//pagead2.googlesyndication.com/relatedsearch",
    "//yandex.ru/soft/browsers/check",
    "//api.facebook.com/restserver.php",
    "//mts0.googleapis.com/maps/vt",
    "//syndication.twitter.com/widgets/timelines/765840589183213568",
    "//www.youtube.com/profile_style",
    "//googletagmanager.com/gtm/js",
    "//mc.yandex.ru/watch/24306916/1",
    "//share.yandex.net/counter/gpp/",
    "//ok.go.mail.ru/lady_on_lady_recipes_r.json",
    "//d1f69o4buvlrj5.cloudfront.net/__efa_15_1_ornpba.xekq.arg/optout_check",
    "//www.googletagmanager.com/gtm/js",
    "//api.vk.com/method/wall.get",
    "//www.sharethis.com/get-publisher-info.php",
    "//google.ru/maps/vt",
    "//pro.netrox.sc/oapi/h_checksite.ashx",
    "//vimeo.com/api/oembed.json/",
    "//de.blog.newrelic.com/wp-admin/admin-ajax.php",
    "//ajax.googleapis.com/ajax/services/search/news",
    "//ssl.google-analytics.com/gtm/js",
    "//pubsub.pubnub.com/subscribe/demo/hello_world/",
    "//pass.yandex.ua/services",
    "//id.rambler.ru/script/topline_info.js",
    "//m.addthis.com/live/red_lojson/100eng.json",
    "//passport.ngs.ru/ajax/check",
    "//catalog.api.2gis.ru/ads/search",
    "//gum.criteo.com/sync",
    "//maps.google.com/maps/vt",
    "//ynuf.alipay.com/service/um.json",
    "//securepubads.g.doubleclick.net/gampad/ads",
    "//c.tiles.mapbox.com/v3/texastribune.tx-congress-cvap/6/15/26.grid.json",
    "//rexchange.begun.ru/banners",
    "//an.yandex.ru/page/147484",
    "//links.services.disqus.com/api/ping",
    "//api.map.baidu.com/",
    "//tj.gongchang.com/api/keywordrecomm/",
    "//data.gongchang.com/livegrail/",
    "//ulogin.ru/token.php",
    "//beta.gismeteo.ru/api/informer/layout.js/120x240-3/ru/",
    "//maps.googleapis.com/maps/api/js/GeoPhotoService.GetMetadata",
    "//a.config.skype.com/config/v1/Skype/908_1.33.0.111/SkypePersonalization",
    "//maps.beeline.ru/w",
    "//target.ukr.net/",
    "//www.meteoprog.ua/data/weather/informer/Poltava.js",
    "//cdn.syndication.twimg.com/widgets/timelines/599200054310604802",
    "//wslocker.ru/client/user.chk.php",
    "//community.adobe.com/CommunityPod/getJSON",
    "//maps.google.lv/maps/vt",
    "//dev.virtualearth.net/REST/V1/Imagery/Metadata/AerialWithLabels/26.318581",
    "//awaps.yandex.ru/10/8938/02400400.",
    "//a248.e.akamai.net/h5.hulu.com/h5.mp4",
    "//nominatim.openstreetmap.org/",
    "//plugins.mozilla.org/en-us/plugins_list.json",
    "//h.cackle.me/widget/32153/bootstrap",
    "//graph.facebook.com/1/",
    "//fellowes.ugc.bazaarvoice.com/data/reviews.json",
    "//widgets.pinterest.com/v3/pidgets/boards/ciciwin/hedgehog-squirrel-crafts/pins/",
    "//se.wikipedia.org/w/api.php",
    "//cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js",
    "//relap.io/api/v2/similar_pages_jsonp.js",
    "//c1n3.hypercomments.com/stream/subscribe",
    "//maps.google.de/maps/vt",
    "//books.google.com/books",
    "//connect.mail.ru/share_count",
    "//tr.indeed.com/m/newjobs",
    "//www-onepick-opensocial.googleusercontent.com/gadgets/proxy",
    "//www.panoramio.com/map/get_panoramas.php",
    "//client.siteheart.com/streamcli/client",
    "//www.facebook.com/restserver.php",
    "//autocomplete.travelpayouts.com/avia",
    "//www.googleapis.com/freebase/v1/topic/m/0344_",
    "//mts1.googleapis.com/mapslt/ft",
    "//api.twitter.com/1/statuses/oembed.json",
    "//fast.wistia.com/embed/medias/o75jtw7654.json",
    "//partner.googleadservices.com/gampad/ads",
    "//pass.yandex.ru/services",
    "//gupiao.baidu.com/stocks/stockbets",
    "//widget.admitad.com/widget/init",
    "//api.instagram.com/v1/tags/partykungen23328/media/recent",
    "//video.media.yql.yahoo.com/v1/video/sapi/streams/063fb76c-6c70-38c5-9bbc-04b7c384de2b",
    "//ib.adnxs.com/jpt",
    "//pass.yandex.com/services",
    "//www.google.de/maps/vt",
    "//clients1.google.com/complete/search",
    "//api.userlike.com/api/chat/slot/proactive/",
    "//www.youku.com/index_cookielist/s/jsonp",
    "//mt1.googleapis.com/mapslt/ft",
    "//api.mixpanel.com/track/",
    "//wpd.b.qq.com/cgi/get_sign.php",
    "//pipes.yahooapis.com/pipes/pipe.run",
    "//gdata.youtube.com/feeds/api/videos/WsJIHN1kNWc",
    "//9.chart.apis.google.com/chart",
    "//cdn.syndication.twitter.com/moments/709229296800440320",
    "//api.flickr.com/services/feeds/photos_friends.gne",
    "//cbks0.googleapis.com/cbk",
    "//www.blogger.com/feeds/5578653387562324002/posts/summary/4427562025302749269",
    "//query.yahooapis.com/v1/public/yql",
    "//kecngantang.blogspot.com/feeds/posts/default/-/Komik",
    "//www.travelpayouts.com/widgets/50f53ce9ada1b54bcc000031.json",
    "//i.cackle.me/widget/32586/bootstrap",
    "//translate.yandex.net/api/v1.5/tr.json/detect",
    "//a.tiles.mapbox.com/v3/zentralmedia.map-n2raeauc.jsonp",
    "//maps.google.ru/maps/vt",
    "//c1n2.hypercomments.com/stream/subscribe",
    "//rec.ydf.yandex.ru/cookie",
    "//cdn.jsdelivr.net",
]

FLASH_URLS = [
    "//vk.com/swf/video.swf",
    "//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf",
]

ANGULAR_URLS = [
    "//gstatic.com/fsn/angular_js-bundle1.js",
    "//www.gstatic.com/fsn/angular_js-bundle1.js",
    "//www.googleadservices.com/pageadimg/imgad",
    "//yandex.st/angularjs/1.2.16/angular-cookies.min.js",
    "//yastatic.net/angularjs/1.2.23/angular.min.js",
    "//yuedust.yuedu.126.net/js/components/angular/angular.js",
    "//art.jobs.netease.com/script/angular.js",
    "//csu-c45.kxcdn.com/angular/angular.js",
    "//elysiumwebsite.s3.amazonaws.com/uploads/blog-media/rockstar/angular.min.js",
    "//inno.blob.core.windows.net/new/libs/AngularJS/1.2.1/angular.min.js",
    "//gift-talk.kakao.com/public/javascripts/angular.min.js",
    "//ajax.googleapis.com/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js",
    "//master-sumok.ru/vendors/angular/angular-cookies.js",
    "//ayicommon-a.akamaihd.net/static/vendor/angular-1.4.2.min.js",
    "//pangxiehaitao.com/framework/angular-1.3.9/angular-animate.min.js",
    "//cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js",
    "//96fe3ee995e96e922b6b-d10c35bd0a0de2c718b252bc575fdb73.ssl.cf1.rackcdn.com/angular.js",
    "//oss.maxcdn.com/angularjs/1.2.20/angular.min.js",
    "//reports.zemanta.com/smedia/common/angularjs/1.2.11/angular.js",
    "//cdn.shopify.com/s/files/1/0225/6463/t/1/assets/angular-animate.min.js",
    "//parademanagement.com.s3-website-ap-southeast-1.amazonaws.com/js/angular.min.js",
    "//cdn.jsdelivr.net/angularjs/1.1.2/angular.min.js",
    "//eb2883ede55c53e09fd5-9c145fb03d93709ea57875d307e2d82e.ssl.cf3.rackcdn.com/components/angular-resource.min.js",
    "//andors-trail.googlecode.com/git/AndorsTrailEdit/lib/angular.min.js",
    "//cdn.walkme.com/General/EnvironmentTests/angular/angular.min.js",
    "//laundrymail.com/angular/angular.js",
    "//s3-eu-west-1.amazonaws.com/staticancpa/js/angular-cookies.min.js",
    "//collade.demo.stswp.com/js/vendor/angular.min.js",
    "//mrfishie.github.io/sailor/bower_components/angular/angular.min.js",
    "//askgithub.com/static/js/angular.min.js",
    "//services.amazon.com/solution-providers/assets/vendor/angular-cookies.min.js",
    "//raw.githubusercontent.com/angular/code.angularjs.org/master/1.0.7/angular-resource.js",
    "//prb-resume.appspot.com/bower_components/angular-animate/angular-animate.js",
    "//dl.dropboxusercontent.com/u/30877786/angular.min.js",
    "//static.tumblr.com/x5qdx0r/nPOnngtff/angular-resource.min_1_.js",
    "//storage.googleapis.com/assets-prod.urbansitter.net/us-sym/assets/vendor/angular-sanitize/angular-sanitize.min.js",
    "//twitter.github.io/labella.js/bower_components/angular/angular.min.js",
    "//cdn2-casinoroom.global.ssl.fastly.net/js/lib/angular-animate.min.js",
    "//www.adobe.com/devnet-apps/flashshowcase/lib/angular/angular.1.1.5.min.js",
    "//eternal-sunset.herokuapp.com/bower_components/angular/angular.js",
    "//cdn.bootcss.com/angular.js/1.2.0/angular.min.js",
    "//elysiumwebsite.s3.amazonaws.com",
]

DIRECTIVES_CAUSING_XSS = [
    Directive.SCRIPT_SRC,
    Directive.OBJECT_SRC,
    Directive.BASE_URI,
]

URL_SCHEMES_CAUSING_XSS = ["data:", "http:", "https:"]


def check_script_unsafe_inline(effective_csp):
    directive_name = effective_csp.get_effective_directive(Directive.SCRIPT_SRC)
    values = effective_csp.directives.get(directive_name, [])

    # Check if unsafe-inline is present.
    if Keyword.UNSAFE_INLINE in values:
        return [
            Finding(
                FindingType.SCRIPT_UNSAFE_INLINE,
                "'unsafe-inline' allows the execution of unsafe in-page scripts "
                "and event handlers.",
                Severity.HIGH,
                directive_name,
                Keyword.UNSAFE_INLINE,
            )
        ]

    return []


def check_script_unsafe_eval(parsed_csp):
    directive_name = parsed_csp.get_effective_directive(Directive.SCRIPT_SRC)
    values = parsed_csp.directives.get(directive_name, [])

    # Check if unsafe-eval is present.
    if Keyword.UNSAFE_EVAL in values:
        return [
            Finding(
                FindingType.SCRIPT_UNSAFE_EVAL,
                "'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().",
                Severity.MEDIUM_MAYBE,
                directive_name,
                Keyword.UNSAFE_EVAL,
            )
        ]

    return []


def check_plain_url_schemes(parsed_csp):
    violations = []
    directives_to_check = parsed_csp.get_effective_directives(DIRECTIVES_CAUSING_XSS)

    for directive in directives_to_check:
        values = parsed_csp.directives.get(directive, [])
        for value in values:
            if value in URL_SCHEMES_CAUSING_XSS:
                violations.append(
                    Finding(
                        FindingType.PLAIN_URL_SCHEMES,
                        value
                        + " URI in "
                        + directive
                        + " allows the execution of unsafe scripts.",
                        Severity.HIGH,
                        directive,
                        value,
                    )
                )

    return violations


def get_scheme_free_url(url):
    # Remove URL scheme.
    url = re.sub(r"^\w[+\w.-]*://", "", url)
    # Remove protocol agnostic "//"
    url = re.sub(r"^//", "", url)
    return url


def get_hostname(url):
    scheme_free_url = (
        get_scheme_free_url(url).replace(":*", "").replace("*", "wildcard_placeholder")
    )
    hostname = re.sub(
        r"wildcard_placeholder",
        "*",
        str(urlparse("https://" + scheme_free_url).hostname),
    )

    # Some browsers strip the brackets from IPv6 addresses when you access the
    # hostname. If the scheme free url starts with something that vaguely looks
    # like an IPv6 address and our parsed hostname doesn't have the brackets,
    # then we add them back to work around this
    ipv6_regex = re.compile(r"^\[[\d:]+\]")
    if ipv6_regex.match(get_scheme_free_url(url)) and not ipv6_regex.match(hostname):
        return "[" + hostname + "]"

    return hostname


def set_scheme(u):
    if u.startswith("//"):
        return u.replace("//", "https://")
    return u


def match_wildcard_urls(csp_url_string, list_of_url_strings):
    # non-Chromium browsers don't support wildcards in domain names. We work
    # around this by replacing the wildcard with `wildcard_placeholder` before
    # parsing the domain and using that as a magic string. This magic string is
    # encapsulated in this function such that callers of this function do not
    # have to worry about this detail.
    csp_url = urlparse(
        set_scheme(
            csp_url_string.replace(":*", "").replace(  # Remove wildcard port
                "*", "wildcard_placeholder"
            )
        )
    )
    list_of_urls = [urlparse(set_scheme(u)) for u in list_of_url_strings]
    host = csp_url.hostname.lower()
    host_has_wildcard = host.startswith("wildcard_placeholder.")
    wildcard_free_host = host.replace("wildcard_placeholder", "", 1)
    path = csp_url.path
    has_path = path != "/"

    for url in list_of_urls:
        domain = url.hostname
        if not domain.endswith(wildcard_free_host):
            # Domains don't match.
            continue

        # If the host has no subdomain wildcard and doesn't match, continue.
        if not host_has_wildcard and host != domain:
            continue

        # If the allowlisted url has a path, check if one of the url paths
        # match.
        if has_path:
            # https://www.w3.org/TR/CSP2/#source-list-path-patching
            if path.endswith("/"):
                if not url.path.startswith(path):
                    continue
            else:
                if url.path != path:
                    # Path doesn't match.
                    continue
        # We found a match.
        return url
    # No match was found.
    return None


def apply_check_function_to_directives(parsed_csp, check):
    directive_names = parsed_csp.directives.keys()

    for directive in directive_names:
        directive_values = parsed_csp.directives[directive]
        if directive_values:
            check(directive, directive_values)


def check_wildcards(parsed_csp):
    violations = []
    directives_to_check = parsed_csp.get_effective_directives(DIRECTIVES_CAUSING_XSS)

    for directive in directives_to_check:
        values = parsed_csp.directives.get(directive, [])
        for value in values:
            url = get_scheme_free_url(value)
            if url == "*":
                violations.append(
                    Finding(
                        FindingType.PLAIN_WILDCARD,
                        directive + " should not allow '*' as source",
                        Severity.HIGH,
                        directive,
                        value,
                    )
                )

    return violations


def check_missing_object_src_directive(parsed_csp):
    object_restrictions = parsed_csp.directives.get(Directive.OBJECT_SRC, None)
    if object_restrictions is None:
        object_restrictions = parsed_csp.directives.get(Directive.DEFAULT_SRC, None)
    if object_restrictions is not None and len(object_restrictions) >= 1:
        return []
    return [
        Finding(
            FindingType.MISSING_DIRECTIVES,
            "Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to 'none'?",
            Severity.HIGH,
            Directive.OBJECT_SRC,
        )
    ]


def check_missing_script_src_directive(parsed_csp):
    if (
        Directive.SCRIPT_SRC in parsed_csp.directives.keys()
        or Directive.DEFAULT_SRC in parsed_csp.directives.keys()
    ):
        return []
    return [
        Finding(
            FindingType.MISSING_DIRECTIVES,
            "script-src directive is missing.",
            Severity.HIGH,
            Directive.SCRIPT_SRC,
        )
    ]


def check_multiple_missing_base_uri_directive(parsed_csps):
    def needs_base_uri(csp):
        return csp.policy_has_script_nonces() or (
            csp.policy_has_script_hashes() and csp.policy_has_strict_dynamic()
        )

    def has_base_uri(csp):
        return Directive.BASE_URI in csp.directives

    if any(map(needs_base_uri, parsed_csps)) and not any(
        map(has_base_uri, parsed_csps)
    ):
        description = "Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to 'none' or 'self'?"
        return [
            Finding(
                FindingType.MISSING_DIRECTIVES,
                description,
                Severity.HIGH,
                Directive.BASE_URI,
            )
        ]
    return []


def check_missing_base_uri_directive(parsed_csp):
    return check_multiple_missing_base_uri_directive([parsed_csp])


def check_missing_directives(parsed_csp):
    return [
        check_missing_object_src_directive(parsed_csp),
        check_missing_script_src_directive(parsed_csp),
        check_missing_base_uri_directive(parsed_csp),
    ]


def check_script_allowlist_bypass(parsed_csp):
    violations = []
    effective_script_src_directive = parsed_csp.get_effective_directive(
        Directive.SCRIPT_SRC
    )
    script_src_values = parsed_csp.directives.get(effective_script_src_directive, [])
    if Keyword.NONE in script_src_values:
        return violations

    for value in script_src_values:
        if value == Keyword.SELF:
            violations.append(
                Finding(
                    FindingType.SCRIPT_ALLOWLIST_BYPASS,
                    "'self' can be problematic if you host JSONP, AngularJS or user uploaded files.",
                    Severity.MEDIUM_MAYBE,
                    effective_script_src_directive,
                    value,
                )
            )
            continue

        if value.startswith("'"):
            continue

        if parsed_csp.is_url_scheme(value) or "." not in value:
            continue

        url = "//" + get_scheme_free_url(value)

        angular_bypass = match_wildcard_urls(url, ANGULAR_URLS)

        jsonp_bypass = match_wildcard_urls(url, JSONP_URLS)

        if jsonp_bypass:
            eval_required = jsonp_bypass.hostname in JSONP_NEEDS_EVAL
            eval_present = Keyword.UNSAFE_EVAL in script_src_values
            if eval_required and not eval_present:
                jsonp_bypass = None

        if jsonp_bypass or angular_bypass:
            bypass_domain = ""
            bypass_txt = ""
            if jsonp_bypass:
                bypass_domain = jsonp_bypass.hostname
                bypass_txt = " JSONP endpoints"
            if angular_bypass:
                bypass_domain = angular_bypass.hostname
                bypass_txt += (
                    " and Angular libraries" if bypass_txt.strip() == "" else ""
                )
            violations.append(
                Finding(
                    FindingType.SCRIPT_ALLOWLIST_BYPASS,
                    bypass_domain
                    + " is known to host"
                    + bypass_txt
                    + " which allow to bypass this CSP.",
                    Severity.HIGH,
                    effective_script_src_directive,
                    value,
                )
            )
        else:
            violations.append(
                Finding(
                    FindingType.SCRIPT_ALLOWLIST_BYPASS,
                    "No bypass found - make sure that this URL "
                    + value
                    + " doesn't serve JSONP replies or Angular libraries.",
                    Severity.MEDIUM_MAYBE,
                    effective_script_src_directive,
                    value,
                )
            )

    return violations


def check_flash_object_allowlist_bypass(parsed_csp):
    violations = []
    effective_object_src_directive = parsed_csp.get_effective_directive(
        Directive.OBJECT_SRC
    )
    object_src_values = parsed_csp.directives.get(effective_object_src_directive, [])

    # If flash is not allowed in plugin-types, continue.
    plugin_types = parsed_csp.directives.get(Directive.PLUGIN_TYPES)
    if plugin_types and "application/x-shockwave-flash" not in plugin_types:
        return []

    for value in object_src_values:
        # Nothing to do here if 'none'.
        if value == Keyword.NONE:
            return []

        url = "//" + get_scheme_free_url(value)
        flash_bypass = match_wildcard_urls(url, FLASH_URLS)

        if flash_bypass:
            violations.append(
                Finding(
                    FindingType.OBJECT_ALLOWLIST_BYPASS,
                    flash_bypass.hostname
                    + " is known to host Flash files which allow to bypass this CSP.",
                    Severity.HIGH,
                    effective_object_src_directive,
                    value,
                )
            )
        elif effective_object_src_directive == Directive.OBJECT_SRC:
            violations.append(
                Finding(
                    FindingType.OBJECT_ALLOWLIST_BYPASS,
                    "Can you restrict object-src to 'none' only?",
                    Severity.MEDIUM_MAYBE,
                    effective_object_src_directive,
                    value,
                )
            )

    return violations


def looks_like_ip_address(maybe_ip):
    if maybe_ip.startswith("[") and maybe_ip.endswith("]"):
        # Looks like an IPv6 address and not a hostname (though it may be some
        # nonsense like `[foo]`)
        return True
    if re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", maybe_ip):
        # Looks like an IPv4 address (though it may be something like
        # `500.600.700.800`
        return True
    # Won't match IP addresses encoded in other manners (eg octal or decimal)
    return False


def check_ip_source(parsed_csp):
    violations = []

    # Function for checking if directive values contain IP addresses.
    def check_ip(directive, directive_values):
        for value in directive_values:
            host = get_hostname(value)
            if looks_like_ip_address(host):
                # Check if localhost.
                # See 4.8 in https://www.w3.org/TR/CSP2/#match-source-expression
                if host == "127.0.0.1":
                    violations.append(
                        Finding(
                            FindingType.IP_SOURCE,
                            directive
                            + " directive allows localhost as source. Please make sure to remove this in production environments.",
                            Severity.INFO,
                            directive,
                            value,
                        )
                    )
                else:
                    violations.append(
                        Finding(
                            FindingType.IP_SOURCE,
                            directive
                            + " directive has an IP-Address as source: {host} (will be ignored by browsers!). ",
                            Severity.INFO,
                            directive,
                            value,
                        )
                    )

    # Apply check to values of all directives.
    apply_check_function_to_directives(parsed_csp, check_ip)
    return violations


def check_deprecated_directive(parsed_csp):
    violations = []

    # More details: https://www.chromestatus.com/feature/5769374145183744
    if Directive.REFLECTED_XSS in parsed_csp.directives:
        violations.append(
            Finding(
                FindingType.DEPRECATED_DIRECTIVE,
                "reflected-xss is deprecated since CSP2. "
                + "Please, use the X-XSS-Protection header instead.",
                Severity.INFO,
                Directive.REFLECTED_XSS,
            )
        )

    # More details: https://www.chromestatus.com/feature/5680800376815616
    if Directive.REFERRER in parsed_csp.directives:
        violations.append(
            Finding(
                FindingType.DEPRECATED_DIRECTIVE,
                "referrer is deprecated since CSP2. "
                + "Please, use the Referrer-Policy header instead.",
                Severity.INFO,
                Directive.REFERRER,
            )
        )

    # More details: https://github.com/w3c/webappsec-csp/pull/327
    if Directive.DISOWN_OPENER in parsed_csp.directives:
        violations.append(
            Finding(
                FindingType.DEPRECATED_DIRECTIVE,
                "disown-opener is deprecated since CSP3. "
                + "Please, use the Cross Origin Opener Policy header instead.",
                Severity.INFO,
                Directive.DISOWN_OPENER,
            )
        )
    return violations


def check_nonce_length(parsed_csp):
    nonce_pattern = re.compile("^'nonce-(.+)'$")
    violations = []

    def check_nonce(directive, directive_values):
        for value in directive_values:
            match = nonce_pattern.match(value)
            if not match:
                continue

            nonce_value = match.group(1)
            if len(nonce_value) < 8:
                violations.append(
                    Finding(
                        FindingType.NONCE_LENGTH,
                        "Nonces should be at least 8 characters long.",
                        Severity.MEDIUM,
                        directive,
                        value,
                    )
                )

            if not CSP.is_nonce(value, True):
                violations.append(
                    Finding(
                        FindingType.NONCE_CHARSET,
                        "Nonces should only use the base64 charset.",
                        Severity.INFO,
                        directive,
                        value,
                    )
                )

    apply_check_function_to_directives(parsed_csp, check_nonce)
    return violations


def check_src_http(parsed_csp):
    violations = []

    def check_directive(directive, directive_values):
        for value in directive_values:
            description = (
                "Use HTTPS to send violation reports securely."
                if directive == Directive.REPORT_URI
                else "Allow only resources downloaded over HTTPS."
            )
            if value.startswith("http://"):
                violations.append(
                    Finding(
                        FindingType.SRC_HTTP,
                        description,
                        Severity.MEDIUM,
                        directive,
                        value,
                    )
                )

    apply_check_function_to_directives(parsed_csp, check_directive)

    return violations


def check_has_configured_reporting(parsed_csp):
    report_uri_values = parsed_csp.directives.get(Directive.REPORT_URI, [])
    if len(report_uri_values) > 0:
        return []

    report_to_values = parsed_csp.directives.get(Directive.REPORT_TO, [])
    if len(report_to_values) > 0:
        return [
            Finding(
                type=FindingType.REPORT_TO_ONLY,
                message="This CSP policy only provides a reporting destination via the 'report-to' directive. This directive is only supported in Chromium-based browsers so it is recommended to also use a 'report-uri' directive.",
                severity=Severity.INFO,
                directive=Directive.REPORT_TO,
            )
        ]

    return [
        Finding(
            type=FindingType.REPORTING_DESTINATION_MISSING,
            message="This CSP policy does not configure a reporting destination. This makes it difficult to maintain the CSP policy over time and monitor for any breakages.",
            severity=Severity.INFO,
            directive=Directive.REPORT_URI,
        )
    ]


def check_strict_dynamic(parsed_csp):
    directive_name = parsed_csp.get_effective_directive(Directive.SCRIPT_SRC)
    values = parsed_csp.directives.get(directive_name, [])

    scheme_or_host_present = any(not v.startswith("'") for v in values)

    # Check if strict-dynamic is present in case a host/scheme allowlist is used.
    if scheme_or_host_present and Keyword.STRICT_DYNAMIC not in values:
        return [
            Finding(
                FindingType.STRICT_DYNAMIC,
                "Host allowlists can frequently be bypassed. Consider using 'strict-dynamic' in combination with CSP nonces or hashes.",
                Severity.STRICT_CSP,
                directive_name,
            )
        ]

    return []


def check_strict_dynamic_not_standalone(parsed_csp):
    directive_name = parsed_csp.get_effective_directive(Directive.SCRIPT_SRC)
    values = parsed_csp.directives.get(directive_name, [])

    if Keyword.STRICT_DYNAMIC in values and (
        not parsed_csp.policy_has_script_nonces()
        and not parsed_csp.policy_has_script_hashes()
    ):
        return [
            Finding(
                FindingType.STRICT_DYNAMIC_NOT_STANDALONE,
                "'strict-dynamic' without a CSP nonce/hash will block all scripts.",
                Severity.INFO,
                directive_name,
            )
        ]

    return []


def check_unsafe_inline_fallback(parsed_csp):
    if (
        not parsed_csp.policy_has_script_nonces()
        and not parsed_csp.policy_has_script_hashes()
    ):
        return []

    directive_name = parsed_csp.get_effective_directive(Directive.SCRIPT_SRC)
    values = parsed_csp.directives.get(directive_name, [])

    if Keyword.UNSAFE_INLINE not in values:
        return [
            Finding(
                FindingType.UNSAFE_INLINE_FALLBACK,
                "Consider adding 'unsafe-inline' (ignored by browsers supporting nonces/hashes) to be backward compatible with older browsers.",
                Severity.STRICT_CSP,
                directive_name,
            )
        ]
    return []


def check_allowlist_fallback(parsed_csp):
    directive_name = parsed_csp.get_effective_directive(Directive.SCRIPT_SRC)
    values = parsed_csp.directives.get(directive_name, [])

    if Keyword.STRICT_DYNAMIC not in values:
        return []

    # Check if there's already an allowlist (url scheme or url)
    if not any(v in ["http:", "https:", "*"] or "." in v for v in values):
        return [
            Finding(
                FindingType.ALLOWLIST_FALLBACK,
                "Consider adding https: and http: url schemes (ignored by browsers "
                "supporting 'strict-dynamic') to be backward compatible with older "
                "browsers.",
                Severity.STRICT_CSP,
                directive_name,
            )
        ]

    return []


def check_requires_trusted_types_for_scripts(parsed_csp):
    directive_name = parsed_csp.get_effective_directive(
        Directive.REQUIRE_TRUSTED_TYPES_FOR
    )
    values = parsed_csp.directives.get(directive_name, [])

    if not TrustedTypesSink.SCRIPT in values:
        return [
            Finding(
                FindingType.REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS,
                "Consider requiring Trusted Types for scripts to lock down DOM XSS "
                + "injection sinks. You can do this by adding "
                + "\"require-trusted-types-for 'script'\" to your policy.",
                Severity.INFO,
                Directive.REQUIRE_TRUSTED_TYPES_FOR,
            )
        ]

    return []


STRICT_CSP_CHECKS = [
    check_strict_dynamic,
    check_strict_dynamic_not_standalone,
    check_unsafe_inline_fallback,
    check_allowlist_fallback,
    check_requires_trusted_types_for_scripts,
]

DEFAULT_CHECKS = [
    check_script_unsafe_inline,
    check_script_unsafe_eval,
    check_plain_url_schemes,
    check_wildcards,
    check_missing_directives,
    check_script_allowlist_bypass,
    check_flash_object_allowlist_bypass,
    check_ip_source,
    check_nonce_length,
    check_src_http,
    check_deprecated_directive,
    check_unknown_directive,
    check_missing_semicolon,
    check_invalid_keyword,
]


class CspEvaluator:
    def __init__(self, parsed_csp, csp_version=None):
        self.version = csp_version or Version.CSP3
        self.csp = parsed_csp
        self.findings = []

    def evaluate(
        self,
        parsed_csp_checks=None,
        effective_csp_checks=None,
    ):
        del self.findings[:]
        checks = effective_csp_checks or DEFAULT_CHECKS

        effective_csp = self.csp.get_effective_csp(self.version, self.findings)

        if parsed_csp_checks:
            for check in parsed_csp_checks:
                self.findings.extend(check(self.csp))

        for check in checks:
            self.findings.extend(check(effective_csp))

        return self.findings


def normalize_directive_value(directive_value):
    directive_value = directive_value.strip()
    directive_value_lower = directive_value.lower()
    if CSP.is_keyword(directive_value_lower) or CSP.is_url_scheme(directive_value):
        return directive_value_lower
    return directive_value


class CspParser:
    def __init__(self, unparsed_csp):
        self.csp = CSP()
        self.parse(unparsed_csp)

    def parse(self, unparsed_csp):
        self.csp = CSP()

        directive_tokens = unparsed_csp.split(";")
        for directive_token in directive_tokens:
            directive_token = directive_token.strip()

            directive_parts = directive_token.split()
            if directive_parts:
                directive_name = directive_parts[0].lower()

                if directive_name in self.csp.directives:
                    continue

                if not CSP.is_directive(directive=directive_name):
                    # Original did not have this implemented
                    pass

                directive_values = []
                for directive_value in directive_parts[1:]:
                    directive_value = normalize_directive_value(directive_value)
                    if directive_value not in directive_values:
                        directive_values.append(directive_value)

                self.csp.directives[directive_name] = directive_values

        return self.csp


class CSPIssue(IScanIssue):
    def __init__(
        self,
        http_service,
        url,
        http_messages,
        issue_name,
        severity,
        issue_detail,
        issue_background=None,
        remed_detail=None,
        remed_background=None,
        issue_type=0,
        confidence="Certain",
    ):
        self._url = url
        self._http_service = http_service
        self._http_messages = http_messages
        self._issue_name = issue_name
        self._severity = severity
        self._issue_detail = issue_detail
        self._issue_background = issue_background
        self._remed_detail = remed_detail
        self._remed_background = remed_background
        self._issue_type = issue_type
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

    def getRemediationDetail(self):
        return self._remed_detail

    def getIssueDetail(self):
        return self._issue_detail

    def getIssueBackground(self):
        return self._issue_background

    def getRemediationBackground(self):
        return self._remed_background

    def getIssueType(self):
        return self._issue_type

    def getIssueName(self):
        return self._issue_name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence


class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._stdout = PrintWriter(self._callbacks.getStdout(), True)
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName("CSP Evaluator for Burp")
        self._callbacks.registerScannerCheck(self)
        self._stdout.println(
            "   ___ ___ ___   ___          _           _              __           ___               "
        )
        self._stdout.println(
            "  / __/ __| _ \ | __|_ ____ _| |_  _ __ _| |_ ___ _ _   / _|___ _ _  | _ )_  _ _ _ _ __ "
        )
        self._stdout.println(
            " | (__\__ \  _/ | _|\ V / _` | | || / _` |  _/ _ \ '_| |  _/ _ \ '_| | _ \ || | '_| '_ \\"
        )
        self._stdout.println(
            "  \___|___/_|   |___|\_/\__,_|_|\_,_\__,_|\__\___/_|   |_| \___/_|   |___/\_,_|_| | .__/"
        )
        self._stdout.println(
            "                                                                                  |_|   "
        )
        self._stdout.println("CSP Evaluator registered")

    def _convert_finding_severity_to_burp_severity(self, finding_severity):
        finding_severity = int(finding_severity)
        if 0 <= finding_severity < 20:
            _issue_severity = "High"
        elif 20 <= finding_severity < 40:
            _issue_severity = "Medium"
        elif 40 <= finding_severity < 60:
            _issue_severity = "Low"
        else:
            _issue_severity = "Information"
        print("Issue severity %s for finding %d" % (_issue_severity, finding_severity))
        return _issue_severity

    def _do_csp_scan(self, baseRequestResponse, headers, url):
        if headers is []:
            return
        issues = []
        _ISSUE_REFERENCES = (
            "<b>References</b>: <br>"
            + "<ul>"
            + "<li><a href=https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</a></li>"
            + "<li><a href=https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy</a></li>"
            + "<li><a href=https://csp-evaluator.withgoogle.com/>https://csp-evaluator.withgoogle.com/</a></li>"
            + "<li><a href=https://github.com/google/csp-evaluator>https://github.com/google/csp-evaluator</a></li>"
            + "<li><a href=https://content-security-policy.com/>https://content-security-policy.com/</a></li>"
            + "<li><a href=https://research.google/pubs/pub45542/>https://research.google/pubs/pub45542/</a></li>"
            + "</ul>"
        )
        _ISSUE_DESCRIPTION = (
            "<b>Directive in question</b>: <br>%(directive)s<br><br>"
            + "<b>Issue</b>: <br>%(description)s<br><br>"
            + "<b>Raw CSP header</b>: <br>%(csp_header)s<br><br>"
            + _ISSUE_REFERENCES
        )
        _ISSUE_NAME = "Content-Security-Policy issue"
        for h in headers:
            if "content-security-policy:" in h.lower():
                _csp_header = h.lower()
                _csp_header = _csp_header.replace("content-security-policy:", "")
                parsed_csp = CspParser(unparsed_csp=_csp_header)
                csp_eval = CspEvaluator(parsed_csp=parsed_csp.csp)
                csp_eval.evaluate(
                    effective_csp_checks=DEFAULT_CHECKS + STRICT_CSP_CHECKS
                )
                for local_finding in csp_eval.findings:
                    if local_finding == []:
                        continue
                    elif type(local_finding) == list:
                        for f in local_finding:
                            _issue_desc = _ISSUE_DESCRIPTION % {
                                "directive": f.directive,
                                "description": f.description,
                                "csp_header": _csp_header,
                            }
                            response = baseRequestResponse.getResponse()
                            index_of_marker = self._helpers.indexOf(
                                response, f.directive, False, 0, len(response)
                            )
                            if index_of_marker != -1:
                                offset = array("i", [0, 0])
                                offsets = []
                                offset[0] = index_of_marker
                                offset[1] = index_of_marker + len(f.directive)
                                offsets.append(offset)
                            else:
                                offsets = None
                            issues.append(
                                CSPIssue(
                                    http_service=baseRequestResponse.getHttpService(),
                                    url=url,
                                    http_messages=[
                                        self._callbacks.applyMarkers(
                                            baseRequestResponse, None, offsets
                                        )
                                    ],
                                    issue_name=_ISSUE_NAME,
                                    severity=self._convert_finding_severity_to_burp_severity(
                                        finding_severity=f.severity
                                    ),
                                    issue_detail=_issue_desc,
                                )
                            )
                    else:
                        _issue_desc = _ISSUE_DESCRIPTION % {
                            "directive": local_finding.directive,
                            "description": local_finding.description,
                            "csp_header": _csp_header,
                        }
                        response = baseRequestResponse.getResponse()
                        index_of_marker = self._helpers.indexOf(
                            response, local_finding.directive, False, 0, len(response)
                        )
                        if index_of_marker != -1:
                            offset = array("i", [0, 0])
                            offsets = []
                            offset[0] = index_of_marker
                            offset[1] = index_of_marker + len(local_finding.directive)
                            offsets.append(offset)
                        else:
                            offsets = None
                        issues.append(
                            CSPIssue(
                                http_service=baseRequestResponse.getHttpService(),
                                url=url,
                                http_messages=[
                                    self._callbacks.applyMarkers(
                                        baseRequestResponse, None, offsets
                                    )
                                ],
                                issue_name=_ISSUE_NAME,
                                severity=self._convert_finding_severity_to_burp_severity(
                                    finding_severity=local_finding.severity
                                ),
                                issue_detail=_issue_desc,
                            )
                        )
        return issues

    def _get_response_headers_and_body(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset() :].tostring()
        return headers, body

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        scan_issues = []

        headers, _ = self._get_response_headers_and_body(baseRequestResponse)

        scan_issues = self._do_csp_scan(
            baseRequestResponse,
            headers=headers,
            url=self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
        )
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []

        headers, _ = self._get_response_headers_and_body(baseRequestResponse)

        scan_issues = self._do_csp_scan(
            baseRequestResponse,
            headers=headers,
            url=self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
        )
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        existing_issue_hostname = existingIssue.getUrl().getHost()
        new_issue_hostname = newIssue.getUrl().getHost()
        # Here I must think about dirreferntiating between each per each url or issue per each host
        if (
            existing_issue_hostname == new_issue_hostname
            and existingIssue.getIssueDetail() == newIssue.getIssueDetail()
        ):
            return -1
        else:
            return 0
