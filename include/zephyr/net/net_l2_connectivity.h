/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public API for managing L2 layers that have separated post-admin-up connect
 *	  or associate phases
 */

#ifndef ZEPHYR_INCLUDE_NET_L2_CONNECTIVITY_H_
#define ZEPHYR_INCLUDE_NET_L2_CONNECTIVITY_H_

#include <zephyr/device.h>
#include <zephyr/net/net_if.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Network Layer 2 connectivity management abstraction layer
 * @defgroup net_l2_connectivity Network L2 Connectivity Abstraction Layer
 * @ingroup networking
 * @{
 */

/**
 * @brief Network L2 connectivity API structure
 *
 * Used to provide an interface to connect parameters and procedures
 */
struct net_l2_connectivity_api {
	int (*connect)(struct net_if *iface);
	int (*disconnect)(struct net_if *iface);

	/* Note to reviewers:
	 * Technically, as long as each iface provides a means by which to set
	 * association/connection parameters, these get/set_opt funcs are not needed.
	 *
	 * However, it can be argued that they should still exist, since they establish a
	 * standardized pattern for doing that.
	 *
	 * The question, then, is: Why limit these to specifically connectivity?
	 * Should these apply to the whole iface, and be distributed to implementations
	 * (where they are present) on not only the connectivity_api, but also the l2_api
	 * and if_api as well?
	 *
	 * For now, I have implemented them just on the connectivity_api, but I wonder if they
	 * should perhaps be more generalized.
	 */
	int (*set_opt)(int optname, const void *optval, size_t optlen);
	int (*get_opt)(int optname, const void *optval, size_t *optlen);
};

/**
 * @brief Network interface connectivity structure
 *
 * Binds L2 connectivity API and settings to an iface / network device
 */
struct net_if_conn {
	/* The network device the connectivity struct is bound to */
	struct net_if_dev *if_dev;

	/* The L2 connectivity implementation associated with the network device */
	struct net_l2_connectivity_api *api;

	/* Per-net-device connectivity settings */
	int timeout;
	bool persistence;

	/* To reviewers: Perhaps connectivity settings should be per-l2, rather than per-iface?
	 *
	 * If so, we could rename net_l2_connectivity_api to just net_l2_conn, and then move
	 * the settings values into that.
	 *
	 * I actually think this would be an overall tidier solution. The net_if_conn struct would
	 * become purely a binding between iface and net_l2_conn.
	 */
};

/** @cond INTERNAL_HIDDEN */
#define NET_IF_CONN_GET_NAME(dev_id, sfx) __net_if_conn_##dev_id##_##sfx
/** @endcond */

/**
 * @brief Associate an L2 connectivity implementation with an existing network device instance
 *
 * @param dev_id Network device id.
 * @param inst Network device instance.
 * @param conn_api Pointer to net_l2_connectivity_api struct to associate.
 */
#define NET_DEVICE_INSTANCE_DEFINE_L2_CONNECTIVITY(dev_id, inst, conn_api)	\
	static STRUCT_SECTION_ITERABLE(net_if_conn,				\
				       NET_IF_CONN_GET_NAME(dev_id, inst)) = {	\
		.if_dev = &(NET_IF_DEV_GET_NAME(dev_id, inst)),			\
		.api = conn_api,						\
	};

/**
 * @brief Associate an L2 connectivity implementation with an existing network device
 *
 * @param dev_id Network device id.
 * @param conn_api Pointer to net_l2_connectivity_api struct to associate.
 */
#define NET_DEVICE_DEFINE_L2_CONNECTIVITY(dev_id, conn_api) \
	NET_DEVICE_INSTANCE_DEFINE_L2_CONNECTIVITY(dev_id, 0, conn_api)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_L2_CONNECTIVITY_H_ */
