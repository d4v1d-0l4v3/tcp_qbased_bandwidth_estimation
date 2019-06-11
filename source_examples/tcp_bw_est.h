/* TCP bandwidth estimator
 * Author: David Olave
 * */

/* Uses /M/M/1 queue model to estimate bottleneck utiliztion */

#ifndef _TCP_BW_EST_
#define _TCP_BW_EST_

/* Includes */
#include <linux/compiler.h>
#include <linux/string.h>

/* Size of averaging table (window) */
#define BW_EST_AVG_WINDOW_SIZE_SHIFT  3
#define BW_EST_AVG_WINDOW_SIZE   (1 << BW_EST_AVG_WINDOW_SIZE_SHIFT)
#define BW_EST_MIN_FIFO_ENTRIES_TO_ENABLE

typedef struct avg_fifo {
    unsigned int rd;
    unsigned int wr;
    unsigned int size;
    void *array;
    unsigned int accum; /* Verify that accumulator does not require larger number */
    unsigned int count;
}avg_fifo_t;

/* Stores packet transmission and arrival times */
typedef struct pkt_series {
    unsigned int sent;
    unsigned int recvd;
}pkt_series_t;

/* Store timing when packet has been sent back to back
 * (less than threshold)
 * */
typedef struct cont_series {
    unsigned int prev_rx;
    unsigned int rx;
    unsigned int delta; /* Time between previous (prev_rx) and current (rx) */
}cont_series_t;

/* Store transmissions and arrival timings of two packets
 * spaced by iddle time longer than the threshold.
 * Also stores the estimated instantaneous bottle neck
 * determined by the spacing of arrival times compared
 * to spacing between transmission times
 * */
typedef struct intvl_series {
    unsigned int prev_rx;
    unsigned int rx;
    unsigned int prev_tx;
    unsigned int tx;
    unsigned int est_bl;  /* Estimated bottle neck length */
}intvl_series_t;

/*!
 * Bandwidth Estimation type
 */
typedef enum _tcp_bw_est_ {
    TCP_BW_EST_TYPE_MIN,
    TCP_BW_EST_TYPE_NO_ACTIVE,
    TCP_BW_EST_TYPE_MD1,
    TCP_BW_EST_TYPE_MM1,
    TCP_BW_EST_TYPE_MG1,
    TCP_BW_EST_TYPE_MAX
}tcp_bw_est_type_t;

/* Collect bw estimation status */
typedef struct __bw_est_stats {
   /* Store number of times time stamp was not found when processing
    * time stamps */
    unsigned int no_ts;
    /* Mean of continuous series (packet link capacity) */
    unsigned int cont_mean;
    /* Increase accuracy of continuous packet calculations  by taking account of
     * residual from previous link capacity calculation */
    unsigned int cont_mean_res;
    /* Mean of continuous series */
    unsigned int intvl_mean;
    /* Keep track of interval divison residual for accurate interval pkt
     * series avg calculation */
    unsigned int intvl_mean_res;
    /* Reflects max segment size at the same time cont mean has been measured */
    unsigned int mss;
    unsigned int cont_push_err;
    unsigned int intvl_push_err;
    unsigned int err_util; /* Counts utilization calculation errors */
    /* Current bw delay product estimate (bdpe). Receive from receiver */
    unsigned int bdpe_rx;
    /* Current bw delay product estimate (bdpe). Sent from receiver */
    unsigned int bdpe_tx;
    /* Keep track of bdpe divison residual for accurate bdp avg calculation */
    unsigned int bdpe_res;
    /* Bdpe sent from receiver*/
    unsigned int bdpe_tx_res;
    unsigned int btl_neck; /* Current bottle neck router length in mss's */
    /* Current bottle neck router length residual (from previous division) */
    unsigned int btl_neck_res;
    unsigned int link_capacity;  /* Current bottle neck link capacity */
    /* Keep track of link capacity divison residual for accurate link_capacity calculation */
    unsigned int link_capacity_res;
    /* Keep track of service variance divison residual for accurate
     * service variance average calculation */
    unsigned int svc_var_mean_res;
    unsigned int svc_var_mean;   /* Service mean variance */
    unsigned int svc_var_push_err;  /* Error inserting variance values in fifo averager */
    unsigned int utl;  /* Current bottle neck utilization  */
    tcp_bw_est_type_t est_mode;   /* Type of estimation mode */

}bw_est_stats_t;

/* Auxiliar variables for M/G/1 queue estimation */
typedef struct _mg1_bw_est {
    /* Used to keep division accuracy on the square root term of M/G/1 equation*/
    unsigned int sqrt_div_res;
    /* Used to keep accuracy on main M/G/1 equation division */
    unsigned int div_res;

}mg1_bw_est_t;

/* Auxiliar variables for M/M/1 queue estimation */
typedef struct _mm1_bw_est {
    /* Used to keep accuracy on main M/M/1 equation division */
    unsigned int util_res;

}mm1_bw_est_t;

/* Markov bandwidth estimation */
typedef struct m_bw_est {
    char enabled;    /* Shows if bw estimator is active */
    /* Set when skb has processed bw estimation for incoming skb */
    char processed;
    cont_series_t cont_series [BW_EST_AVG_WINDOW_SIZE];
    pkt_series_t pkt_series [BW_EST_AVG_WINDOW_SIZE];
    intvl_series_t intvl_series[BW_EST_AVG_WINDOW_SIZE];
    unsigned int vars[BW_EST_AVG_WINDOW_SIZE]; /* Variances */
    avg_fifo_t cont_series_fifo;
    avg_fifo_t pkt_series_fifo;
    avg_fifo_t intvl_series_fifo;
    avg_fifo_t avg_svc_var_fifo;
    mg1_bw_est_t mg1;
    mm1_bw_est_t mm1;
}m_bw_est_t;

struct tcp_sock;
struct sk_buff;
struct sock;

/* Function prototypes */
int tcp_bw_est_m_process (struct sock *sk, struct sk_buff *skb);

/* Init bandwidth estimator */
int bw_est_init (m_bw_est_t *bw_est_p, bw_est_stats_t *bw_est_stats_p);

/* Inline functions here */
static
inline unsigned int fifo_inc (unsigned int idx, unsigned max_size) {
    idx++;
    if (unlikely (idx == max_size)) {
        idx = 0;
    }
    return idx;
}

static
inline unsigned int fifo_dec (unsigned int idx, unsigned max_size) {
   if (unlikely (idx == 0)) {
       idx = max_size - 1;
   } else {
       idx--;
   }
   return idx;
}

static
inline unsigned int bw_est_fifo_full(avg_fifo_t *fifo_p) {
    unsigned int wr = fifo_inc(fifo_p->wr, fifo_p->size);
    return (fifo_p->rd == wr);
}

static
inline unsigned int bw_est_fifo_empty(avg_fifo_t *fifo_p) {
    return (fifo_p->rd == fifo_p->wr);
}

/* Get (peek, do not removed) last entry stored in pkt series fifo.
 */
static
inline pkt_series_t * __bw_est_fifo_peek_last_series (avg_fifo_t *fifo_p) {
    pkt_series_t *wr_entry = (pkt_series_t *)fifo_p->array;
    return &(wr_entry[fifo_p->wr]);
}

/* Circular buffer where oldest entries are over written
 * return:  1 if a new entry was added and the latest entry was removed.
 *          Otherwise, error
 * */
static inline int bw_est_fifo_push_pkt_series (avg_fifo_t *fifo_p,
      const pkt_series_t *pkt_series_p)
{
    pkt_series_t *wr_entry = (pkt_series_t *)fifo_p->array;
    if (likely (bw_est_fifo_full(fifo_p))) {
        /* Removed oldest entry */
        fifo_p->rd = fifo_inc(fifo_p->rd, BW_EST_AVG_WINDOW_SIZE);

    } else {
       fifo_p->count++;
    }
    /* Add entry */
    memcpy (&wr_entry[fifo_p->wr], pkt_series_p, sizeof(fifo_p->array[fifo_p->wr]));
    fifo_p->wr = fifo_inc(fifo_p->wr, BW_EST_AVG_WINDOW_SIZE);
    return 1;
}

/* Circular buffer where oldest entries are over written, new entries are added and
 * accumulator is adjusted for the added and removed entries
 * 1 if a new entry was added and the latest entry was removed.
 *   Otherwise, error
 * */
static inline int bw_est_fifo_push_cont_series (avg_fifo_t *fifo_p,
      const cont_series_t *pkt_series_p)
{
    cont_series_t *array = (cont_series_t *)fifo_p->array;
    if (likely (bw_est_fifo_full(fifo_p))) {
        /* Remove oldest entry from accumulator.
         * WARNING: Accumulatore mus not be negative */
        if (unlikely (fifo_p->accum < array[fifo_p->rd].delta)) {
            /* Log error */
            return 0;
        } else {
            fifo_p->accum -= array[fifo_p->rd].delta;
            fifo_p->rd = fifo_inc(fifo_p->rd, BW_EST_AVG_WINDOW_SIZE);
        }

    } else {
        fifo_p->count++;
    }

    /* Add new value */
    fifo_p->accum += pkt_series_p->delta;

    /* Add packet and adjust average */
    memcpy (&array[fifo_p->wr], pkt_series_p, sizeof(array[fifo_p->wr]));

    fifo_p->wr = fifo_inc(fifo_p->wr, BW_EST_AVG_WINDOW_SIZE);
    return 1;
}

/* Circular buffer where oldest entries are over written, new entries are added and
 * accumulator is adjusted for the added and removed entries
 * 1 if a new entry was added and the latest entry was removed.
 *   Otherwise, error
 * */
static inline int bw_est_fifo_push_intvl_series (avg_fifo_t *fifo_p,
      const intvl_series_t *intvl_series_p)
{
   intvl_series_t *array = (intvl_series_t *)fifo_p->array;
    if (likely (bw_est_fifo_full(fifo_p))) {
        /* Remove oldest entry from accumulator. */
        if (fifo_p->accum < array[fifo_p->rd].est_bl) {
            /* Log error */
            return 0;
        } else {
           fifo_p->accum -= array[fifo_p->rd].est_bl;
           fifo_p->rd = fifo_inc(fifo_p->rd, BW_EST_AVG_WINDOW_SIZE);
        }
    } else {
       fifo_p->count++;
    }
    /* Add packet and adjust average */
    memcpy (&array[fifo_p->wr], intvl_series_p, sizeof(array[fifo_p->wr]));
    /* Add new value */
    fifo_p->accum += intvl_series_p->est_bl;
    fifo_p->wr = fifo_inc(fifo_p->wr, BW_EST_AVG_WINDOW_SIZE);

    return 1;
}

/* Circular buffer where oldest entries are over written, new entries are added and
 * accumulator is adjusted for the added and removed entries
 * 1 if a new entry was added and the latest entry was removed.
 *   Otherwise, error
 * */
static inline int bw_est_fifo_push_var (avg_fifo_t *fifo_p,
      const unsigned int var)
{
   unsigned int *array = (unsigned int *)fifo_p->array;
    if (likely (bw_est_fifo_full(fifo_p))) {
        /* Remove oldest entry from accumulator. */
        if (fifo_p->accum < array[fifo_p->rd]) {
            /* Log error */
            return 0;
        } else {
           fifo_p->accum -= array[fifo_p->rd];
           fifo_p->rd = fifo_inc(fifo_p->rd, BW_EST_AVG_WINDOW_SIZE);
        }
    } else {
       fifo_p->count++;
    }
    /* Add packet and adjust average */
    array[fifo_p->wr] = var;
    /* Add new value */
    fifo_p->accum += var;
    fifo_p->wr = fifo_inc(fifo_p->wr, BW_EST_AVG_WINDOW_SIZE);

    return 1;
}

#endif /* _TCP_BW_EST_ */
