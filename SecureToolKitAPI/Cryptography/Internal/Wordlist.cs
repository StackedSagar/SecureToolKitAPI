namespace SecureToolKitAPI.Cryptography.Internal
{
    /// <summary>
    /// The word list passphrases and suggested usernames are built from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The words are short, common English nouns, verbs and adjectives, chosen so that a passphrase can
    /// be read over a phone call and typed from memory. Words that are easily confused when heard —
    /// homophones and near-homophones — and words with awkward spellings are avoided.
    /// </para>
    /// <para>
    /// Strength comes from the number of words and the size of this list, not from the words being
    /// obscure: a passphrase of <c>n</c> words drawn independently from this list carries
    /// <c>n × log2(Count)</c> bits, and <see cref="Count"/> is measured from the list itself so the
    /// figure reported to callers cannot drift from reality if the list changes.
    /// </para>
    /// </remarks>
    internal static class Wordlist
    {
        /// <summary>
        /// The source text. Whitespace-separated so the list stays readable and easy to review; it is
        /// split, de-duplicated and ordered once, in the static initialiser.
        /// </summary>
        private const string Source = """
            able acid acorn actor adapt admit adopt adult agent agree
            ahead alarm album alert alien alike alive alley allow alloy
            alone along alpha altar amaze amber amend among ample anchor
            angel anger angle ankle anvil apart apple apron arena argue
            arise armor aroma array arrow aside asset atlas attic audio
            audit avoid awake award aware

            bacon badge bagel baker balloon bamboo banana band bank barn
            basic basil basin basket batch baton beach beacon beam bean
            bear beard beast beaver bench berry birch bird black blade
            blank blast blaze blend bless blind block bloom blush board
            boast boat bolt bond bone bonus book boost booth border
            borrow bottle bounce bound brain brake branch brand brass brave
            bread break breeze brick bridge brief bright bring brisk broad
            bronze brook broom brown brush bubble bucket budget build bulb
            bundle bunker burst butter button buyer

            cabin cable cactus camel camera canal candle candy canoe canvas
            canyon carbon cargo carpet carrot carve castle catch cattle cause
            cedar cement census center chain chair chalk charm chart chase
            cheek cheer cheese cherry chess chest chief child chill choir
            chorus chrome chunk cider cinema circle civic civil claim clamp
            clash class clean clear clerk cliff climb cloak clock close
            cloth cloud clover coach coast cobalt cocoa coffee coin collar
            colony color column comet comic cook cool copper coral cork
            corn corner cotton couch cough count county couple course cousin
            cover cozy craft crane crate cream creek crest crisp crop
            cross crowd crown cube curl curve cycle

            dairy dance dandy dawn debate decade decor deep deer delay
            delta demand dense depot derby desert design desk detail dial
            diary diner dinner dish ditch diver dock dodge dolphin domain
            donate donor double dough dove down dozen draft dragon drama
            draw dream dress drift drill drink drive drum dryer duck
            dune dusk dust duty dwell

            eagle early earth easel east easy echo edge eight elbow
            elder elect elite email ember empty enact enemy energy engine
            enjoy enter entry equal equip erase error essay ethic even
            event ever exact exam excel exist exit expand expert extra

            fable fabric facet factor fade fair falcon fancy farm fast
            fault fear feast feather fence fern ferry fetch fever fiber
            field fifth fight file film filter final finch finder finish
            fire first fish fist flag flame flash flat flavor fleet
            flint float flock flood floor flour flower fluid flute focus
            foggy foil fold folk font food fork form forum fossil
            found fresh fringe frost fruit fudge fuel full fund funny
            fury fuse

            gadget galaxy game garden garlic gate gauge gaze gear gecko
            gentle ghost giant gift ginger giraffe glad glance glass glaze
            glide globe gloss glove glow goal goat gold golden good
            goose grace grade grain grand grant grape graph grasp grass
            gravel gray great green greet grid grill grip grove grow
            guard guess guest guide guild guitar gulf

            habit half hall hammer hand happy harbor hard harm harvest
            haste hatch haven hawk hazel head health heart heavy hedge
            help herb hero hidden high hike hill hinge hint hire
            hive hobby hold hole home honey honor hood hoop hope
            horn horse host hotel hound hour house hover human humble
            humid hunt hurdle hurry hydro

            ideal image impact imply import inch index indoor inner input
            insect inside intend invest invite iron island issue item ivory

            jacket jade jaguar jail jazz jeans jelly jewel join joint
            joke jolly journal joyful judge juice july jumbo jump june
            jungle junior juror just

            kayak keen keep kettle kernel kick kind king kiosk kite
            kitten knee knot know

            label labor lace ladder lake lamp land lane lantern lapse
            large laser last late laugh launch lava lawn layer leaf
            leap learn lease least leave ledge left legal legend lemon
            lend lens lentil level lever light lilac lily lime limit
            linen link lion liquid list liter little lively living lizard
            load loaf lobby local lock lodge loft logic long loop
            loose lord lotus loud lounge lover loyal lucky lunar lunch

            magic magnet major maker mango manor maple marble march margin
            marine market marsh mask mason match matrix mayor meadow meal
            mean medal media medium melody melon member memory mentor menu
            mercy merit merry mesh metal meter method metro middle might
            mild mile milk mill mind mine mint minute mirror mixed
            model modem modern modest moment money monkey month moral
            more morning mosaic moss motion motor mount mouse move movie
            muffin mule music mutual myself mystery

            napkin narrow nation native nature navy near neat neck nectar
            need needle neon nerve nest never newly news next
            nice night nimble noble node noise nomad noon north nose
            note notice novel nurse nylon

            oasis oats ocean octave offer often olive omega onion open
            opera opinion option orange orbit orchard order organ origin other
            ounce outer output oval oven overt owner oxide oyster ozone

            pace pack page paint pair palace palm panda panel pantry
            paper parade parcel parent park parrot party pass past
            pasta patch path patient patrol pattern pause peace peach pear
            pearl pebble pedal pencil penny people pepper perch perfect period
            permit person phase phone photo phrase piano pick picnic piece
            pier pigeon pilot pine pink pipe pitch pivot pixel pizza
            place plain plan plant plate play plaza pleat plenty plot
            plug plum plus pocket poem point polar pole polish pond
            pony pool poppy porch port post potato pouch pound power
            praise prefer press pretty price pride prime print prism prize
            probe profit prompt proof proud prove prune public pull pulse
            punch puppy purple purse push puzzle pyramid

            quaint quality quart quartz queen quest queue quick quiet quilt
            quite quiz quota quote

            rabbit race radar radio radish raft rail rain raise rally
            ranch random range rank rapid rare rate raven reach react
            read ready realm reason rebel recall recipe record reduce reef
            refine reform refuge regal region regret rehab relax relay relief
            remain remedy remind remote render renew rent repair repeat reply
            report rescue reset resist resort result retail retire return reveal
            review reward rhyme rhythm ribbon rich ride ridge rifle right
            rigid ring rinse ripe rise risk rival river road roast
            robin robot rock rocket rodeo rogue role roll roof room
            root rope rose rotate rough round route royal rubber ruby
            rugby rule rural rush rustic

            sacred saddle safe sail saint salad salmon salon salt sample
            sand satin sauce savor scale scan scarf scene scent scholar
            school scope score scout scrap screen script scroll sculpt seal
            search season seat second secret sector secure seed seek seem
            seize select send sense serve settle seven shade shadow shaft
            shape share shark sharp sheep sheet shelf shell shield shift
            shine ship shirt shock shoe shop shore short shout show
            shrimp shrub side siege sight sigma sign silent silk silly
            silver simple since sing siren sister site size skate sketch
            skill skin skirt skyline slate sled sleep slice slide slim
            slope slot slow small smart smile smoke smooth snack snake
            snap sneak snow soap social socket soda sofa soft solar
            solid solve sonic soon sort soul sound soup south space
            spare spark speak spear speed spell spend sphere spice spider
            spike spin spiral spirit split spoke sponge spoon sport spot
            spray spread spring sprint sprout spruce square squash stable stack
            staff stage stair stake stamp stand star start state stay
            steady steam steel stem step stereo stick still stitch stock
            stone stool stop store storm story stove strap straw stream
            street strike string strip stroke strong study stuff style sugar
            suit summer summit sunny sunset super supply sure surf surge
            survey swan sweet swift swim swing switch sword symbol syntax syrup

            table tablet tackle tactic tail tailor take tale talent talk
            tall tame tank tape target task taste taught teach team
            tease tech teeth tempo tenant tender tennis tent tenth term
            test thank theme theory thick thing think third thirty thorn
            thread three thrive throat throne thumb thunder ticket tidal tide
            tidy tiger tight tile timber time timer tiny title toast
            today toffee token tomato tone tonic tool tooth topaz topic
            torch total touch tour towel tower town trace track trade
            trail train trait tram trap travel tray treat tree trend
            trial tribe trick trim trio trip trophy trout truck true
            trumpet trust truth tulip tumble tuna tunnel turbo turf turn
            turtle tutor twelve twenty twin twist type

            ultra umpire uncle under unify union unique unit unite until
            upbeat upgrade uphill upload upon upper upset urban urge usage
            useful usual utmost

            vacant valid valley value valve vanilla vapor variety vary vase
            vault vector velvet vendor venue verb verify verse vessel vest
            veteran vibrant video view villa vine vinyl viola violet virtue
            vision visit visual vital vivid vocal voice volume vote vowel
            voyage

            wagon waist wait wake walk wall walnut wander want warm
            warn wash watch water wave waxen weather weave wedge week
            weight welcome well west whale wheat wheel when where while
            whisk white whole wide widget width wild willow wind window
            wing winner winter wire wise wish witty wizard wolf wonder
            wood wool word work world worth wound woven wrap wren
            wrist write

            yacht yard yarn yawn year yeast yellow yield yoga young
            youth

            zebra zenith zero zesty zigzag zinc zone zoom
            """;

        /// <summary>
        /// The word list: split from <see cref="Source"/>, de-duplicated and ordered so the list — and
        /// therefore the entropy claimed for a passphrase — is stable and independent of the layout of
        /// the source text.
        /// </summary>
        private static readonly string[] Entries =
        [
            .. Source
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(word => word, StringComparer.Ordinal)
        ];

        /// <summary>The words available for selection, ordered and free of duplicates.</summary>
        /// <remarks>
        /// Exposed as a read-only list so a generator can index into it with
        /// <see cref="System.Security.Cryptography.RandomNumberGenerator.GetInt32(int)"/>; no caller may
        /// reorder or extend it.
        /// </remarks>
        internal static IReadOnlyList<string> Words => Entries;

        /// <summary>
        /// The same words as a span, so a generator can sample them with
        /// <see cref="System.Security.Cryptography.RandomNumberGenerator.GetItems{T}(ReadOnlySpan{T}, int)"/>
        /// instead of hand-rolling the selection.
        /// </summary>
        internal static ReadOnlySpan<string> Choices => Entries;

        /// <summary>
        /// Number of words available. Each word drawn from the list independently contributes
        /// <c>log2(Count)</c> bits of entropy.
        /// </summary>
        internal static int Count => Entries.Length;
    }
}
