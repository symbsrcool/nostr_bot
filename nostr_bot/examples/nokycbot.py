"""
NoKYCTranslate.com Bot

Listens for DMs to itself

"""
from aionostr.event import Event, EventKind
from aionostr.key import PrivateKey, PublicKey

from nostr_bot import CommunicatorBot
import json
from loguru import logger


class NoKYCTranslateBot(CommunicatorBot):
    """
    Run this like:

    nostr-bot run -r 'wss://relay.damus.io,wss://snort.social'  -c nostr_bot.examples.nokycbot.NoKYCTranslateBot
    """
    LIMIT = 100
    LISTEN_KIND = 4
    LISTEN_PUBKEY = None
    # replace this with your public key hex - you can easily get it off of nostr.band
    PUBLIC_KEY_HEX = "0302009dd0596881b4bcefbad3d13e57b23e719543ae57c53f81686e1ff47dca"
    PRIVATE_KEY4DECODING = PrivateKey.from_nsec('<put your nsec here>>')

    EVENTS_SEEN = set()

    async def handle_event(self, event):
        logger.info("Got event {}".format(event.id))
        from_pubkey = event.pubkey
        if event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
            if event.id not in NoKYCTranslateBot.EVENTS_SEEN:
                #logger.info("event tags are {}".format(event.tags))
                has_p_tag, for_me = event.has_tag('p', matches=[NoKYCTranslateBot.PUBLIC_KEY_HEX])
                #logger.info(
                #    "event.has_tag('p', matches=['0302009dd0596881b4bcefbad3d13e57b23e719543ae57c53f81686e1ff47dca'])) = {}".format(for_me))
                if for_me:
                    # todo left off here
                    # decrypt the message
                    decrypted_message = NoKYCTranslateBot.PRIVATE_KEY4DECODING.decrypt_message(event.content, from_pubkey)
                    logger.critical("{} from {} on {}".format(decrypted_message, from_pubkey[:10], event.created_at))

                    NoKYCTranslateBot.EVENTS_SEEN.add(event.id)

        #await self.reply(dm)
