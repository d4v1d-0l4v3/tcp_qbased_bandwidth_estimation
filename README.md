# tcp_qbased_bandwidth_estimation
TCP Q-based Bandwidth Estimation Implemented on TCP Stack

Date Posted in Github: June 10th 2019.

This repository stores patches for a kernel stack implementation of Markovian Q-based alogorithm to estimate network capacity on all levels of network congestion. The implementation uses linux standard and non-standard methods to insert Q-based congestion estimation algorithms on the kernel stack.

Currently, this repo contains kernel patches and example code extracted from the listed kernel patches for user inspection. The kernel patches are targeted for a custom Freescale mpc8377 power-pc running a kernel 3.12.38 in order to use the offload timestamp capabilitties of the power-pc gianfar-named ethernet controller.

This work was performed to determine the feasibility of Markov queue theory to estimate bandwidth capacity under any level of network congestion.
