/* Functions required to estimate network bandwith for tcp
 * Author: David Olave
 * */

#include <linux/tcp_bw_est.h>
#include <linux/kernel.h>
#include <linux/tcp.h>
#include <net/tcp.h>

/* Local defines */

/* Fuunction prototypes below */

/* Functions below */

/* Init fifo averge structure
 * return: 0 - Success initializing. Otherwise,
 *         Error.
 *  */
static int bw_est_fifo_init (avg_fifo_t *fifo_p, void *array,
      unsigned int array_size)
{
    int ret = -1;         /* Assume error initializing fifo */
    if ((fifo_p != NULL) && (array != NULL)) {
       memset (fifo_p, 0, sizeof(*fifo_p));
       fifo_p->array = array;
       fifo_p->size = array_size;
       ret = 0;
    }

    return ret;
}

/* Init bandwidth estimator
 * return: 0 - Success initializing bandwidth estimator Otherwise error
 *  */
int bw_est_init (m_bw_est_t *bw_est_p, bw_est_stats_t *bw_est_stats_p)
{
   int ret = -1;         /* Assume error initializing bw estimator */
   if (bw_est_p == NULL) {
       printk(KERN_ERR"Error, invalid bw estimator addres. "
             "Bw estimator will not be activated\n");
       bw_est_p->enabled = 0;
       return ret;
   }

   /* Clear stats and overall states*/
   memset (bw_est_stats_p, 0, sizeof(*bw_est_stats_p));
   bw_est_stats_p->est_mode = TCP_BW_EST_TYPE_NO_ACTIVE;

   /* Sledge hammer. Clear all estimation specific variables */
   memset(bw_est_p, 0, sizeof(*bw_est_p));

   if (bw_est_fifo_init(&bw_est_p->cont_series_fifo,
         bw_est_p->cont_series, BW_EST_AVG_WINDOW_SIZE)) {
       printk(KERN_ERR"Error initializing continuous series packets. "
             "Bw estimator will not be activated\n");
       bw_est_p->enabled = 0;
       return ret;
   }

   if (bw_est_fifo_init(&bw_est_p->pkt_series_fifo,
         bw_est_p->pkt_series, BW_EST_AVG_WINDOW_SIZE)) {
          printk(KERN_ERR"Error initializing series packets. "
                "Bw estimator will not be activated\n");
          bw_est_p->enabled = 0;
       return ret;
   }

   if (bw_est_fifo_init(&bw_est_p->intvl_series_fifo, bw_est_p->intvl_series,
         BW_EST_AVG_WINDOW_SIZE)) {
          printk(KERN_ERR"Error initializing interval series packets. "
                "Bw estimator will not be activated\n");
          bw_est_p->enabled = 0;
   }

   if (bw_est_fifo_init(&bw_est_p->avg_svc_var_fifo, bw_est_p->vars,
         BW_EST_AVG_WINDOW_SIZE)) {
          printk(KERN_ERR"Error initializing interval series packets. "
                "Bw estimator will not be activated\n");
          bw_est_p->enabled = 0;
   }

   bw_est_p->enabled = 1;
   bw_est_p->processed = 0;
   ret = 0;
   return ret;
}

#define BITS_PER_LONG_LONG 64
/**
 * ll_sqrt - rough approximation to sqrt for 64 bit
 *           operations.
 * @return: square root without significant decimal numbers
 *
 */
u64 ll_sqrt(u64 x)
{
    u64 b, m, y = 0;

    if (x <= 1)
        return x;

    m = 1ULL << (BITS_PER_LONG_LONG - 2);
    while (m != 0) {
        b = y + m;
        y >>= 1;

        if (x >= b) {
            x -= b;
            y += m;
        }
        m >>= 2;
    }

    return y;
}

/*
 * Estimates router bottleneck utilization
 * Equation used:
 * utlization = (1 + length) − sqroot(1 + length^2)
 * @return: Estimating bottleneck utilization. Otherwise,
 *          -1 - Error
 *
 * Note: a scaler might be needed at the result since, the ppc
 *       cannot process floating numbers. The our resulting equation is
 *       scale * (1 + length) − sqroot(scaler * (1 + length^2))
 *
 *       Also, estimation is not completely accurate when the mss varies
 *       continuously
 */

/* Generate large numbers but produce good accuracy */
#define TCP_BW_EST_UTIL_SCALE_SHIFT   17ULL
#define TCP_BW_EST_UTIL_SCALE         (1ULL<<TCP_BW_EST_UTIL_SCALE_SHIFT)
/* Scale to the power of two */
#define TCP_BW_EST_UTIL_SCALE_POW2    (1ULL<<(TCP_BW_EST_UTIL_SCALE_SHIFT*2ULL))
#define TCP_BW_EST_BL_SCALE_SHIFT     6UL
#define TCP_BW_EST_BL_SCALE           (1UL<<TCP_BW_EST_BL_SCALE_SHIFT)

inline int tcp_bw_utlization_est(struct tcp_sock *tp)
{
   int ret = -1;    /* Assume bw utilization calculation error */
   u64 bl = (u64)((tp->bw_est_stats.btl_neck < 0)? 0 : tp->bw_est_stats.btl_neck);
   u64 tmp;

   switch (tp->bw_est_stats.est_mode) {
       case TCP_BW_EST_TYPE_NO_ACTIVE:
           return ret;
           break;
       case TCP_BW_EST_TYPE_MD1:
           ret = (int)(TCP_BW_EST_UTIL_SCALE * (bl + TCP_BW_EST_BL_SCALE) -
                 ll_sqrt( TCP_BW_EST_UTIL_SCALE_POW2 * ((bl*bl)+
                      TCP_BW_EST_BL_SCALE ) ));
           ret = ret >> TCP_BW_EST_BL_SCALE_SHIFT;
           break;
       case TCP_BW_EST_TYPE_MM1:

           tmp = (bl * TCP_BW_EST_UTIL_SCALE) +
              tp->m_bw_est.mm1.util_res;
           tp->m_bw_est.mm1.util_res = __div64_32 (&tmp, bl + TCP_BW_EST_BL_SCALE);
           ret = (int)tmp;

           break;
       case TCP_BW_EST_TYPE_MG1: {

           /* Round trip and variance are obtained from sender measurements */
           u32 cont_mean2 = tp->bw_est_stats.cont_mean * tp->bw_est_stats.cont_mean;
           u64 var = tp->bw_est_stats.svc_var_mean * tp->bw_est_stats.svc_var_mean;
           u32 divd = var - cont_mean2;
           u64 sqrt2 = (TCP_BW_EST_UTIL_SCALE_POW2 * 2ULL * bl * var) + tp->m_bw_est.mg1.sqrt_div_res;
           u64 sqrt;
           s64 div;

           /* Handling division by zero. The smaller possible scale is 1  */
           tp->m_bw_est.mg1.sqrt_div_res = __div64_32 (&sqrt2, likely(cont_mean2)? cont_mean2 : 1);
           sqrt = ll_sqrt ((TCP_BW_EST_UTIL_SCALE_POW2 * (bl * bl + 1ULL)) +
                 sqrt2);
           div = ((sqrt - (TCP_BW_EST_UTIL_SCALE * (bl + 1ULL))) * tp->bw_est_stats.cont_mean *
                 tp->bw_est_stats.cont_mean) + tp->m_bw_est.mg1.div_res;
           /* Handling division by zero. The smaller possible scale is 1 */
           tp->m_bw_est.mg1.div_res = __div64_32(&div, likely(divd)? divd : 1);

           /* Hopefully, we have number that does not exceed  TCP_BW_EST_UTIL_SCALE */
           ret = (int)div;
           ret = ret >> TCP_BW_EST_BL_SCALE_SHIFT;
       }

          break;
       default:
          /* Log error */
          ret = -1;
          break;
   }

   return ret;

}

/*!
 * Estimates router bottleneck available bandwidth
 * Equation used:
 * BDPE = service_rate × (1 − utilization) × RTT/PacketSize
 *
 * @return: 0 - Success estimating bottleneck bandwidth. Otherwise,
 *              Error
 *
 * Note: Pointer argument is not checked for sanity to improve
 *       performance.
 */
inline int tcp_bw_est(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    int util = tcp_bw_utlization_est(tp);
    u64 bdpe_64; /* Estimated bw product */

    if (unlikely(util < 0)) {
        tp->bw_est_stats.err_util++;
        return -1;
    }

    /* scale * link (1 - p) = link ( scale - (scale * p) ) */
    bdpe_64 = tp->bw_est_stats.link_capacity * (TCP_BW_EST_UTIL_SCALE - util);
    bdpe_64 = ((bdpe_64 >> TCP_BW_EST_UTIL_SCALE_SHIFT) *
          (jiffies_to_usecs(tp->rcv_rtt_est.rtt)>>3)) + tp->bw_est_stats.bdpe_res;
    tp->bw_est_stats.bdpe_res = __div64_32 (&bdpe_64,
          inet_csk(sk)->icsk_ack.rcv_mss * USEC_PER_SEC /* Normalizing rtt */);
    tp->bw_est_stats.bdpe_tx = (u32)bdpe_64;
    tp->bw_est_stats.tx_bw_found = 1;
    tp->bw_est_stats.utl = util;

    return 0;
}

/* Calculate variance
 * return: 0 - Success calculating variance. Otherwise,
 *         Failure
 */
int tcp_bw_est_calc_var(struct tcp_sock *tp, int std)
{
   unsigned int var = (unsigned int)((int) std * (int)std);
   avg_fifo_t *var_fifo_p = &(tp->m_bw_est.avg_svc_var_fifo);

   if (unlikely (!bw_est_fifo_push_var(var_fifo_p, var))) {
       tp->bw_est_stats.svc_var_push_err++;
       return -1;
   }
   /* Get arrival delta mean. Window size is multiple
    * of two */
   if (likely(var_fifo_p->count)) {
       unsigned int accum = var_fifo_p->accum + tp->bw_est_stats.svc_var_mean_res;
       tp->bw_est_stats.svc_var_mean = accum / var_fifo_p->count;
       tp->bw_est_stats.svc_var_mean_res = accum % var_fifo_p->count;
    } else {
       tp->bw_est_stats.svc_var_mean = var_fifo_p->accum + tp->bw_est_stats.svc_var_mean_res;
       tp->bw_est_stats.svc_var_mean_res = 0;
    }
    return 0;
}

/*!
 * Process continuous series delta histogram
 * Classify continuous packet intervals on a specific histogram bin.
 * Note: Not checking function arguments sanity for performance
 * 		 considerations
 *
 * @return: 0 - Success classifying current delta. Otherwise, error
 */
int tcp_bw_est_process_cont (struct tcp_sock *tp, unsigned int delta_us)
{


	if (delta_us < 60) {
		tp->bw_est_stats.cont_delta_hist[0]++;
	} else if (delta_us < 80) {
		tp->bw_est_stats.cont_delta_hist[1]++;
	} else if (delta_us < 100) {
		tp->bw_est_stats.cont_delta_hist[2]++;
	} else if (delta_us < 140) {
		tp->bw_est_stats.cont_delta_hist[3]++;
	} else if (delta_us < 160) {
		tp->bw_est_stats.cont_delta_hist[4]++;
	} else if (delta_us < 200) {
		tp->bw_est_stats.cont_delta_hist[5]++;
	} else {
		tp->bw_est_stats.cont_delta_hist[6]++;
	}

	return 0;
}


/* Markov queue based bandwidth estimation algorithm. Collect data,
 * analyze it and calculate approximate network capacity.
 * return: 0 - Success processsing Markov based bandwidth estimation. Otherwise,
 *             error.
 * */
int tcp_bw_est_m_process (struct sock *sk, struct sk_buff *skb) {

    int ret = -1; /* Assume error */
    pkt_series_t pkt_series; /* Samples received */
    struct tcp_sock *tp = tcp_sk(sk);
    avg_fifo_t *pkt_series_fifo_p = &tp->m_bw_est.pkt_series_fifo;

    /* No checking for pointer sanity to improve performance */
    /* Store current sent time. At this point, it is assume the system has
     * detected and store a timestmap */
    return 0;


//    pkt_series.recvd = tcp_bw_get_stamp_us();
    pkt_series.recvd = tcp_bw_get_skb_stamp_us(skb);
//    pkt_series.recvd = skb->h.th->seq;

    pkt_series.sent = tp->rx_opt.rcv_tsval_us;

    if (!TCP_BW_IS_ACTIVE(tp)) return 0;

//    if (TCP_BW_IS_ACTIVE(tp)) {
//         static unsigned int i = 0;
//         if ((i % 50) == 0) {
//             printk(KERN_ERR"send_cwnd=%u ssth=%u flight=%u\n", tp->snd_cwnd,
//                   tp->snd_ssthresh, tcp_packets_in_flight(tp));
//         }
//         i++;
//     }

    if (likely (!bw_est_fifo_empty(pkt_series_fifo_p))) {
        const struct inet_connection_sock *icsk = inet_csk(sk);
        pkt_series_t *last_pkt_series_p =
              __bw_est_fifo_peek_last_series(pkt_series_fifo_p);
        /* No need to check for return pointer sanity for now */
        /* Measure tx delta */
        unsigned int delta = (unsigned int)((signed int)pkt_series.sent -
              (signed int)last_pkt_series_p->sent);
        avg_fifo_t *intvl_series_fifo_p = &tp->m_bw_est.intvl_series_fifo;
        int cont_mean;
        int intvl_mean;

//        if (TCP_BW_IS_ACTIVE(tp)) {
//            printk(KERN_ERR"%s:sent=%u last sent=%u d=%d\n", __FUNCTION__, pkt_series.sent,
//              last_pkt_series_p->sent, delta);
//        }

        /* TODO: Remove Change condition */
        if (delta > BW_EST_CONT_TH_US) {
            avg_fifo_t *cont_series_fifo_p = &tp->m_bw_est.cont_series_fifo;
            int cont_delta = pkt_series.recvd - last_pkt_series_p->recvd;
            /* The packet is a continuous series */
            cont_series_t cont_series;

            tp->bw_est_stats.cont_hits++;
            cont_series.prev_rx = last_pkt_series_p->recvd;
            cont_series.rx = pkt_series.recvd;
            cont_series.delta = likely(cont_delta > 0)? cont_delta : 0;
            if (unlikely (!bw_est_fifo_push_cont_series(cont_series_fifo_p, &cont_series))) {
                tp->bw_est_stats.cont_push_err++;
                return -1;
            }
            /* Get arrival delta mean. Window size is multiple
             * of two */
            if (likely(cont_series_fifo_p->count)) {
                unsigned int accum = cont_series_fifo_p->accum + tp->bw_est_stats.cont_mean_res;
                tp->bw_est_stats.cont_mean = accum / cont_series_fifo_p->count;
                tp->bw_est_stats.cont_mean_res = accum % cont_series_fifo_p->count;
            } else {
                tp->bw_est_stats.cont_mean = cont_series_fifo_p->accum + tp->bw_est_stats.cont_mean_res;
                tp->bw_est_stats.cont_mean_res = 0;
            }

            /* Calculate variance. Only executed in M/G/1 queue to save cpu cycles */
            if (tp->bw_est_stats.est_mode == TCP_BW_EST_TYPE_MG1) {
                tcp_bw_est_calc_var(tp, tp->bw_est_stats.cont_mean - cont_series.delta);
            }

            /* Process continuous series histogram */
            tcp_bw_est_process_cont(tp, cont_series.delta);

            /* Calculate bottleneck link speed. */
            {
            u64 link_capacity = ((u64)icsk->icsk_ack.rcv_mss * (u64)USEC_PER_SEC) +
                  (u64)tp->bw_est_stats.link_capacity_res;

            cont_mean = tp->bw_est_stats.cont_mean;
            tp->bw_est_stats.link_capacity_res =
                  __div64_32(&link_capacity, likely(cont_mean)? cont_mean : 1);
            tp->bw_est_stats.link_capacity = link_capacity;
            }

        } else {
           /* The packet is a interval series */
           unsigned int delta_rx, delta_tx;
           int delta;
           intvl_series_t intvl_series;
           intvl_series.prev_rx = last_pkt_series_p->recvd;
           intvl_series.rx = pkt_series.recvd;
           intvl_series.prev_tx = last_pkt_series_p->sent;
           intvl_series.tx = pkt_series.sent;
           /* Taking in account u32 wrapping */
           delta_rx = (unsigned int)((signed int)intvl_series.rx - (signed int)intvl_series.prev_rx);
           delta_tx = (unsigned int)((signed int)intvl_series.tx - (signed int)intvl_series.prev_tx);
//           intvl_series.est_bl = (unsigned int)((signed int)delta_rx - (signed int)delta_tx);
           delta = ((signed int)delta_rx - (signed int)delta_tx);

//           if (delta < 0) {
//              /* Invalid value, return */
//              bw_est_fifo_push_pkt_series(pkt_series_fifo_p, &pkt_series);
//              return 0;
//           }
//           else {intvl_series.est_bl = delta; }
           {intvl_series.est_bl = delta; }
//           if (TCP_BW_IS_ACTIVE(tp)) {
//               static unsigned int i = 0;
//               if ((i % 50) == 0) {
//                   printk(KERN_ERR"%s: rx=%u prx=%u tx=%u ptx=%u cbl=%d drx=%u dtx=%u\n", __FUNCTION__, intvl_series.rx,
//                   intvl_series.prev_rx, intvl_series.tx, intvl_series.prev_tx, intvl_series.est_bl,
//                   delta_rx, delta_tx);
//               }
//           }

           if (unlikely(!bw_est_fifo_push_intvl_series(intvl_series_fifo_p, &intvl_series))) {
               tp->bw_est_stats.intvl_push_err++;
               return -1;
           }

           if (likely(intvl_series_fifo_p->count)) {
                   int accum = intvl_series_fifo_p->saccum + tp->bw_est_stats.intvl_mean_res;
                   tp->bw_est_stats.intvl_mean =  (signed)accum / (signed)intvl_series_fifo_p->count;
                   tp->bw_est_stats.intvl_mean_res =
                         accum % intvl_series_fifo_p->count;
//                 printk(KERN_ERR"%s: intvl saccum=%d res=%d cnt=%d m=%d a=%d c=%d bl=%d\n", __FUNCTION__, intvl_series_fifo_p->saccum,
//                       tp->bw_est_stats.intvl_mean_res, intvl_series_fifo_p->count, tp->bw_est_stats.intvl_mean, accum,
//                       intvl_series_fifo_p->count, intvl_series.est_bl);
           } else {
               tp->bw_est_stats.intvl_mean = intvl_series_fifo_p->saccum + tp->bw_est_stats.intvl_mean_res;
               tp->bw_est_stats.intvl_mean_res = 0;
           }

           tp->bw_est_stats.intvl_hits++;
        }

        cont_mean = tp->bw_est_stats.cont_mean;
        intvl_mean = (tp->bw_est_stats.intvl_mean < 0) ? 0 : tp->bw_est_stats.intvl_mean;
        /* Calculate approximate router bottleneck packet count */
        /* Get arrival delta mean. Window size is multiple
         * of two */

        {
        const int btl_neck = (intvl_mean + tp->bw_est_stats.btl_neck_res) * TCP_BW_EST_BL_SCALE;
        tp->bw_est_stats.btl_neck = (signed)btl_neck / (signed)(likely(cont_mean)? cont_mean : 1);
        tp->bw_est_stats.btl_neck_res = (signed)btl_neck % (signed)cont_mean;

        }

        /* Estimate available bandwidth */
        ret = tcp_bw_est(sk);
    }

    bw_est_fifo_push_pkt_series(pkt_series_fifo_p, &pkt_series);
    /* Find the send delta */

    return 0;
}

#define BYTES_PER_ASCII 2
#define NIBBLES_PER_BYTE 2
/*
 * Print packet series samples
 */
void tcp_bw_est_print_pkt_series (struct tcp_sock *tp)
{

    if (TCP_BW_IS_ACTIVE(tp)) {
       /* Should be less than BW_EST_AVG_WINDOW_SIZE */
#define PKT_SAMPLES_PER_PRINTED_LINE   (BW_EST_AVG_WINDOW_SIZE>>7)
#define PKT_STRING_FORMAT "idx=%u tx=%u rx=%u "

        unsigned int i = 0;
        unsigned char str [] = {PKT_STRING_FORMAT};
        unsigned char *buf = (unsigned char *)
              kmalloc(PKT_SAMPLES_PER_PRINTED_LINE * sizeof(u32) *
              BYTES_PER_ASCII * sizeof(str) * 3 /* rx, tx, and idx numbers */
              * NIBBLES_PER_BYTE * 4 /* Extra space */,
              GFP_ATOMIC);
        int len = 0; /* Chars written */
        pkt_series_t *pkt_series_p = &tp->m_bw_est.pkt_series[0];

        if (!buf) {
            printk(KERN_ERR"%s: Error, could not allocate print memory\n", __FUNCTION__);
            return;
        }
        if (!tp) {
            printk(KERN_ERR"%s: Error, invalid tcp socket pointer\n", __FUNCTION__);
            return;
        }
        for (; i < BW_EST_AVG_WINDOW_SIZE>>6; i++) {
            len += sprintf (buf + len, PKT_STRING_FORMAT, i, pkt_series_p[i].sent,
                  pkt_series_p[i].recvd);
            if (i && ((i % (PKT_SAMPLES_PER_PRINTED_LINE - 1)) == 0)) {
                printk(KERN_ERR "%s\n", buf);
                len = 0; /* Reset print offset */

            }
        }

        kfree(buf);
    }
}

/*
 * Print continuous series samples
 */
void tcp_bw_est_print_cont_series (struct tcp_sock *tp)
{
    if (TCP_BW_IS_ACTIVE(tp)) {
       /* Should be less than BW_EST_AVG_WINDOW_SIZE */
#define CONT_SAMPLES_PER_PRINTED_LINE   (BW_EST_AVG_WINDOW_SIZE>>5)
//#define CONT_STRING_FORMAT "idx=%u prx=%u rx=%u d=%u "
#define CONT_STRING_FORMAT "-idx=%u d=%u "

        unsigned int i = 0;
        unsigned char str [] = {PKT_STRING_FORMAT};
        unsigned char *buf = (unsigned char *)
              kmalloc(PKT_SAMPLES_PER_PRINTED_LINE * sizeof(u32) *
              BYTES_PER_ASCII * sizeof(str) * 4 /* prev rx, rx, delta and idx numbers */
              * NIBBLES_PER_BYTE * 4 /* Extra space */,
              GFP_ATOMIC);
        int len = 0; /* Chars written */
        cont_series_t *cont_series_p = &tp->m_bw_est.cont_series[0];

        if (!buf) {
            printk(KERN_ERR"%s: Error, could not allocate print memory\n", __FUNCTION__);
            return;
        }
        if (!tp) {
            printk(KERN_ERR"%s: Error, invalid tcp socket pointer\n", __FUNCTION__);
            return;
        }
        printk(KERN_ERR"%s: ih=%d ch=%d h0=%d h1=%d h2=%d h3=%d h4=%d h5=%d h6=%d\n", __FUNCTION__,
        	tp->bw_est_stats.intvl_hits, tp->bw_est_stats.cont_hits,
        	tp->bw_est_stats.cont_delta_hist[0], tp->bw_est_stats.cont_delta_hist[1],
        	tp->bw_est_stats.cont_delta_hist[2], tp->bw_est_stats.cont_delta_hist[3], tp->bw_est_stats.cont_delta_hist[4],
        	tp->bw_est_stats.cont_delta_hist[5], tp->bw_est_stats.cont_delta_hist[6]);
        for (; i < BW_EST_AVG_WINDOW_SIZE; i++) {
//            len += sprintf (buf + len, CONT_STRING_FORMAT, i, cont_series_p[i].prev_rx,
//                  cont_series_p[i].rx, cont_series_p[i].delta);
            len += sprintf (buf + len, CONT_STRING_FORMAT, i, cont_series_p[i].delta);
            if (i && ((i % (CONT_SAMPLES_PER_PRINTED_LINE - 1)) == 0)) {
                printk(KERN_ERR "%s\n", buf);
                len = 0; /* Reset print offset */

            }
        }

        kfree(buf);
    }
}

/*
 * Print interval packet series samples
 */
void tcp_bw_est_print_intvl_series (struct tcp_sock *tp) {

    if (TCP_BW_IS_ACTIVE(tp)) {
        /* Should be less than BW_EST_AVG_WINDOW_SIZE */
#define INTVL_SAMPLES_PER_PRINTED_LINE   (BW_EST_AVG_WINDOW_SIZE>>6)
#define INTVL_STRING_FORMAT "idx=%u tx=%u txprev=%u rx=%u rxprev=%u d=%d a=%d "
//#define INTVL_STRING_FORMAT "d=%d a=%d "

        unsigned int i = 0;
        unsigned char str [] = {INTVL_STRING_FORMAT};
        unsigned char *buf = (unsigned char *)
              kmalloc(INTVL_SAMPLES_PER_PRINTED_LINE * (sizeof(u32) *
                    /* rx, tx, rxprev, txprev, idx, accum and delta numbers */
                    BYTES_PER_ASCII * NIBBLES_PER_BYTE * 6)
                    + sizeof(str) + 4 /* Extra space */,
              GFP_ATOMIC);
        int len = 0; /* Chars written */
        intvl_series_t *intvl_series_p = &tp->m_bw_est.intvl_series[0];

        if (!buf) {
            printk(KERN_ERR"%s: Error, could not allocate print memory\n", __FUNCTION__);
            return;
        }
        if (!tp) {
            printk(KERN_ERR"%s: Error, invalid tcp socket pointer\n", __FUNCTION__);
            return;
        }

        printk(KERN_ERR"%s: ih=%d ch=%d h0=%d h1=%d h2=%d h3=%d h4=%d h5=%d h6=%d\n", __FUNCTION__,
         tp->bw_est_stats.intvl_hits, tp->bw_est_stats.cont_hits,
         tp->bw_est_stats.cont_delta_hist[0], tp->bw_est_stats.cont_delta_hist[1],
         tp->bw_est_stats.cont_delta_hist[2], tp->bw_est_stats.cont_delta_hist[3], tp->bw_est_stats.cont_delta_hist[4],
         tp->bw_est_stats.cont_delta_hist[5], tp->bw_est_stats.cont_delta_hist[6]);
        for (; i < BW_EST_AVG_WINDOW_SIZE; i++) {
            len += sprintf (buf + len, INTVL_STRING_FORMAT, i, intvl_series_p[i].tx,
                  intvl_series_p[i].prev_tx, intvl_series_p[i].rx,
                  intvl_series_p[i].prev_rx, intvl_series_p[i].est_bl,
                  intvl_series_p[i].accum);
//            len += sprintf (buf + len, INTVL_STRING_FORMAT, intvl_series_p[i].est_bl,
//                  intvl_series_p[i].accum);
            if (i && ((i % (INTVL_SAMPLES_PER_PRINTED_LINE - 1)) == 0)) {
                printk(KERN_ERR "%s\n", buf);
                len = 0; /* Reset print offset */

            }
        }

        kfree(buf);
    }
}

/*
 * Print packet series samples
 */
void tcp_bw_est_print_series (struct tcp_sock *tp) {

    if (TCP_BW_IS_ACTIVE(tp)) {
        /* Should be less than BW_EST_AVG_WINDOW_SIZE */
#define SAMPLES_PER_PRINTED_LINE   (BW_EST_AVG_WINDOW_SIZE>>6)
#define STRING_FORMAT "idx=%u tx=%u rx=%u "
//#define INTVL_STRING_FORMAT "d=%d a=%d "

        unsigned int i = 0;
        unsigned char str [] = {STRING_FORMAT};
        unsigned char *buf = (unsigned char *)
              kmalloc(SAMPLES_PER_PRINTED_LINE * (sizeof(u32) *
                    /* rx, tx, rxprev, txprev, idx, accum and delta numbers */
                    BYTES_PER_ASCII * NIBBLES_PER_BYTE * 6)
                    + sizeof(str) + 4 /* Extra space */,
              GFP_ATOMIC);
        int len = 0; /* Chars written */
        pkt_series_t *pkt_series_p = &tp->m_bw_est.pkt_series[0];

        if (!buf) {
            printk(KERN_ERR"%s: Error, could not allocate print memory\n", __FUNCTION__);
            return;
        }
        if (!tp) {
            printk(KERN_ERR"%s: Error, invalid tcp socket pointer\n", __FUNCTION__);
            return;
        }

        printk(KERN_ERR"%s: ih=%d ch=%d h0=%d h1=%d h2=%d h3=%d h4=%d h5=%d h6=%d\n", __FUNCTION__,
         tp->bw_est_stats.intvl_hits, tp->bw_est_stats.cont_hits,
         tp->bw_est_stats.cont_delta_hist[0], tp->bw_est_stats.cont_delta_hist[1],
         tp->bw_est_stats.cont_delta_hist[2], tp->bw_est_stats.cont_delta_hist[3], tp->bw_est_stats.cont_delta_hist[4],
         tp->bw_est_stats.cont_delta_hist[5], tp->bw_est_stats.cont_delta_hist[6]);
        for (; i < BW_EST_AVG_WINDOW_SIZE; i++) {
            len += sprintf (buf + len, STRING_FORMAT, i,
                  pkt_series_p[i].sent, pkt_series_p[i].recvd);
//            len += sprintf (buf + len, INTVL_STRING_FORMAT, intvl_series_p[i].est_bl,
//                  intvl_series_p[i].accum);
            if (i && ((i % (SAMPLES_PER_PRINTED_LINE - 1)) == 0)) {
                printk(KERN_ERR "%s\n", buf);
                len = 0; /* Reset print offset */

            }
        }

        kfree(buf);
    }
}

