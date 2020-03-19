#include "apiorig.h"
#include "sample.h"
#include "fips202.h"
#include "randombytes.h"
#include <math.h>
#include <stdbool.h>
/*#include "CDT.h"*/
#define IFMORE64(val, gauge, expr) ((((gauge) - (val)) >> (63)) & (expr))
#define SIGMA_2     0.84932180028801904272150283410289 /**This is the same for any sigma*/

#define TESLA_K     ((PARAM_SIGMA/SIGMA_2)) /** parameter for the Bernulli sample*/




//Interface of Gauss sampler
/*extern void sample_gauss(int64_t *x,unsigned char *seed);*/


void sample_y(int64_t *mat_y,const unsigned char *seed, int ctsm)
{
  int64_t val;
  unsigned char buf[3*PARAM_N+68];
  int pos=0, i=0,ctr=0;
  cshake256_simple(buf,3*PARAM_N+68,(ctsm<<8)+ctr,seed,CRYPTO_RANDOMBYTES);
  ctr++;
  do
  {
    if(pos >= 3*PARAM_N+66)
    {
      cshake256_simple(buf,3*PARAM_N+68,(ctsm<<8)+ctr,seed,CRYPTO_RANDOMBYTES);
      ctr++;
      pos = 0;
    }
    val  = (*(uint32_t *)(buf+pos)) &((1<<PARAM_B_BITS)-1);

    if(val < (PARAM_B))
      mat_y[i++] = val;

    pos+=(PARAM_B_BITS+7)/8;
    
  }
  while(i< PARAM_N);
}
bool Bernoulli(int64_t r,int64_t t) {
    // restriction: 20-bit exponent
    static const double exp[4][32] = {
{
       1.000000000000000000000000000000000000000,
       0.9931034757050423185036910970337836883342,
       0.9862545134574355785532295284626857480370,
       0.9794527852443647064526079096656409618111,
       0.9726979653151629767190245748686993647487,
       0.9659897301657110510406328147983878442075,
       0.9593277585229436096411426850297501514742,
       0.9527117313294628330376275733039359370464,
       0.9461413317282579972952028634139444547582,
       0.9396162450475304509642674943285974790067,
       0.9331361587856232469329743760294605700149,
       0.9267007625960547074397641995137461814058,
       0.9203097482726552054683992120398885728257,
       0.9139628097348064506912074089606206497436,
       0.9076596430127825730354300653446240541939,
       0.9013999462331923018228917062585280599138,
       0.8951834196045215432749149848353809218941,
       0.8890097654027756639827153825881278285851,
       0.8828786879572207927186624481620577554630,
       0.8767898936362234577060141420428303429993,
       0.8707430908331878811742458716426654945650,
       0.8647379899525902577041315333616898932356,
       0.8587743033961093475115143198405201229406,
       0.8528517455488527204314526510788772738457,
       0.8469700327656779909453622626606718283910,
       0.8411288833576083891431186247183612224492,
       0.8353280175783420170300523501679310641080,
       0.8295671576108541440755804562244435933516,
       0.8238460275540919003560831530977423857924,
       0.8181643534097607300697726499480482032054,
       0.8125218630692019725959192208000287330813,
       0.8069182863003609426351109307382602935745,
    },
    {
       1.000000000000000000000000000000000000000,
       0.8013533547348448853014360024020238023856,
       0.6421671991447901435520990885361082949899,
       0.5146028393353567949615138031103389376902,
       0.4123787116574645628762829501812088095721,
       0.3304610640079425136657367255968469700518,
       0.2648160822520110386427359775633937048954,
       0.2122112559003876626498347772728579008265,
       0.1700562018282702993664596823721100274522,
       0.1362751078285502665431896811243122152003,
       0.1092045148252614790336908808925505841755,
       0.08751140430741438932181710545108177387096,
       0.07012755741930387581174944227534622125221,
       0.05619695339731962211520311214261073170285,
       0.04503361713081981756557407030746998115439,
       0.03608784016362704079104696849263576108990,
       0.02891911178025740270881736962034014175892,
       0.02317442724106124202322214233073493296697,
       0.01857090501368300214259893202181372071872,
       0.01488185703317702422448458895674359737242,
       0.01192562605822075416264731332508075892013,
       0.009556640449068485933547932494537663639409,
       0.007658245883855745733213252220586177488069,
       0.006136961030412119113613798718768243652996,
       0.004917874309597762078434500836520102660418,
       0.003940955076160475815410744557646513861265,
       0.003158097571140513417834541874831847126324,
       0.002530752083213415880099207756859667092488,
       0.002028026671885268137629694802605432815618,
       0.001625165977007002152368672390592664799299,
       0.001302332207675492962255361340929509585583,
       0.001043628283599992990680392772683753187211,
    },
    {
       1.000000000000000000000000000000000000000,
       0.0008363150261590224838175948634668919618664,
       6.994228229793664614022810053550776226766E-7,
       5.849378164962062141800694553713955364080E-10,
       4.891922853044261933714335817245165760091E-13,
       4.091188588811631820980268674299049072167E-16,
       3.421522491673494146624567228974241093236E-19,
       2.861470672127602045808857833249235579020E-22,
       2.393090920013671153911222023497224802880E-25,
       2.001377895372152573540620873125728199468E-28,
       1.673782406922251143196301455976006382399E-31,
       1.399809377429694080519713238459959773796E-34,
       1.170681616102759582191921137969137958171E-37,
       9.790586263948660970048425514835472315726E-41,
       8.188014407446390607554776697414914004495E-44,
       6.847759483353981143169706115445063106502E-47,
       5.726884151451879028581922721519734963171E-50,
       4.789479268931169489836842368015499687647E-53,
       4.005513480084266893641618538091771175582E-56,
       3.349871110876990851914687859892180159520E-59,
       2.801547545722444311641259133696531015336E-62,
       2.342976308986611252527681741477518767773E-65,
       1.959466293140107735490412251928259264803E-68,
       1.638731104205192019341460620615156561793E-71,
       1.370495446280968963490405651616796961863E-74,
       1.146165935007289751934974490786715133450E-77,
       9.585557939182019929310069621674697561067E-81,
       8.016546138655836648179659770366562470444E-84,
       6.704357993654966710081525385471551371367E-87,
       5.606955330843004979724325074845304039941E-90,
       4.689180994186438274901237411044377928463E-93,
       3.921632525817422183487209786964188679022E-96,
    },
    {
       1.000000000000000000000000000000000000000,
       3.279720208415070849511437313442845572049E-99,
       1.075656464548619576996105957816160759241E-197,
       3.527852244092416867701205429176828017354E-296,
       0.0, //1.157036829725235684846597592971115522130E-394,
       0.0, //3.794757072330362822984179325895001739601E-493,
       0.0, //1.244574145614790164421483826708861369492E-591,
       0.0, //4.081854976243748333833085373719150816208E-690,
       0.0, //1.338734225340624035671068059395577810176E-788,
       0.0, //4.390673692546539885303083523641015104410E-887,
       0.0, //1.440018123800130650179933687692257736549E-985,
       0.0, //4.722856541111243792392893687450711480790E-1084,
       0.0, //1.548964803932784911856522252784413723787E-1182,
       0.0, //5.080171169582042686165032799298310367596E-1281,
       0.0, //1.666154004708585127475599062254307600314E-1379,
       0.0, //5.464518959574445751821254025781569850318E-1478,
       0.0, //1.792209326098360733936984040511230702018E-1576,
       0.0, //5.877945144514749342252805126448619414271E-1675,
       0.0, //1.927801547442026745635659839368563783562E-1773,
       0.0, //6.322649692959460052123974844457523536224E-1872,
       0.0, //2.073652196872848403693964499787509791847E-1970,
       0.0, //6.800999015308187895062908658140760435018E-2069,
       0.0, //2.230537390791726162610922316873435789575E-2167,
       0.0, //7.315538556205048464380282575338749298238E-2266,
       0.0, //2.399291963822530804340508402885831198671E-2364,
       0.0, //7.869006339636635358347842104367137992701E-2463,
       0.0, //2.580813911225257950810460329438748638334E-2561,
       0.0, //8.464347538804217163848939701382467691360E-2660,
       0.0, //2.776069167406455911138732462626930722106E-2758,
       0.0, //9.104730148300953789040659289210446622887E-2857,
       0.0, //2.986096745954858308481849072786241225257E-2955,
       0.0, //9.793561841990632763171439856430939280811E-3054,
    },
    };

    //assert(t >= 0 && t < (1LL << 20));
    // compute the actual Bernoulli parameter c = exp(-t/f):
    double c = 4611686018427387904.0; // this yields a fraction of 2^62, to keep only 62 bits of precision in this implementation

    for (int64_t i = 0, s = t; i < 3; i++, s >>= 5) {
        c *= exp[i][s & 31]; 
    }
    // sample from Bernoulli_c:
    bool ret = (((r & 0x3FFFFFFFFFFFFFFFLL) - llrint(c)) >> (63)) & 1;
    return ret;
}

void sample_gauss_poly(int64_t *x, const unsigned char *seed, uint64_t ctr)
{
  static const int64_t cdt[16][4] = {
    {0x0000000200000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000300000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000320000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000200000000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x0000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x2000000000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x2000010000000000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x2000010000020000LL, 0x0000000000000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x2000010000020000LL, 0x0100000000000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x2000010000020000LL, 0x0100000020000000LL},
    {0x0000000321020100LL, 0x2001000200010000LL, 0x2000010000020000LL, 0x0100000020000001LL},
  };

  unsigned char seed_ex[PARAM_N*16];
  int16_t dmsp = ctr<<8;
  cshake256_simple(seed_ex, PARAM_N*16,dmsp++,seed, CRYPTO_RANDOMBYTES); 
  int64_t i, j=0, x_ind;
  int64_t *buf = (int64_t*)seed_ex;
  int64_t scnt=0LL, sign, sbuf=0LL, k, uc, ub, y, z;
  uint64_t r, s, t, u;
  for(x_ind=0;x_ind<PARAM_N;x_ind++){
    if((j+66)> (PARAM_N*2)){
	  cshake256_simple((uint8_t*)buf, PARAM_N*16,dmsp++,seed, CRYPTO_RANDOMBYTES);// printf("seed is not enough!!!\n");
	  j=0;
    }
    do {
      ub=buf[j++]; uc=64;
      do {
        // sample x from D^+_{\sigma_2} and y from U({0, ..., k-1}):
        do {
          r = buf[j++];
	  s = buf[j++];
	  t = buf[j++];
	  u = buf[j++];
          //*
          if (uc <= 64 - 6) {
            ub = (ub << 6) ^ ((r >> 58) & 63); uc += 6;
          }
          //*/
          r &= 0x00000003FFFFFFFFLL;
        } while (r > 0x0000000321020100LL); 
        y = 0;
        for (i = 0; i < 15; i++) {
          y += ((r > cdt[i][0]) || (r == cdt[i][0] && s > cdt[i][1]) || (r == cdt[i][0] && s == cdt[i][1] && t > cdt[i][2]) || (r == cdt[i][0] && s == cdt[i][1] && t == cdt[i][2] && u >= cdt[i][3])); // effectively stop incrementing k when r < cdt[i]
        }
	// caveat: the next sampler works exclusively for TESLA_K <= 256.
        do {
	  do {
                if (uc < 6) {
                    ub = buf[j++]; uc = 64;
                }
                z = ub & 63; ub >>= 6; uc -= 6;
            } while (z == 63);
            /*
            int64_t b = y % 9;
            if (b != 8 && uc <= 64 - 3) {
                ub = (ub << 3) ^ b; uc += 3;
            }
            //*/
            if (uc < 2) {
                ub = buf[j++]; uc = 64;
            }
            z = ((z % 7) << 2) + (ub & 3); ub >>= 2; uc -= 2;
        } while (z >= TESLA_K);
        k = TESLA_K*y + z;
        // sample a bit from Bernoulli_{exp(-y*(y + 2*k*x)/(2*k^2*sigma_2^2))}:
      } while (!Bernoulli(buf[j++], z*((k << 1) - z)));
    
      if(scnt==0LL){
        sbuf = buf[j++]; scnt=64;
      }
      sign = sbuf >> (63); sbuf <<= 1; scnt--;
    } while ((k | (sign & 1)) == 0);
    if(scnt==0LL){
      sbuf = buf[j++]; scnt=64;
    }
    sign = sbuf >> (63); sbuf <<= 1; scnt--;
    k = ((k << 1) & sign) - k;
    x[x_ind]=(k<<48)>>48;
  }

}

void generate_c(uint32_t *pos_list, int16_t *sign_list, unsigned char *c_bin)
{
  int i;
  double c[PARAM_N];

  //Now generate the F(c) value
  unsigned short nonce = 0x1234;
  const int R_LENGTH = 840;
  unsigned char r[R_LENGTH];

  //Use the hash value as key to generate some randomness
  cshake256_simple(r, R_LENGTH, nonce, c_bin, CRYPTO_RANDOMBYTES);
  //Now populate the vector
  int cnt =0;
  int pos;

  //Use rejection sampling to determine positions to be set in the new vector
  for(i=0; i<PARAM_N; i++)
    c[i] = 0;

  i=0;
  while(i<PARAM_W)
  {
    //sample a position (0 to k-1). Use two bytes
    pos = 0;
    pos = (r[cnt]<<8) | (r[cnt+1]);
    pos = pos & (PARAM_N-1);
    cnt += 2;

    if (pos<PARAM_N)
    {
      //position is between [0,n-1]
      if (c[pos] == 0)
      {
        //position has not been set yet. Determine sign
        if ((r[cnt] & 1) ==1)
          c[pos] = -1;
        else
          c[pos] = 1;
        pos_list[i] = pos;
        sign_list[i] = c[pos];
        i++;
        cnt++;
      }
    }
  }
}