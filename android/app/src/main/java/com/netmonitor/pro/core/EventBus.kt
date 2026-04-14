package com.netmonitor.pro.core

object EventBus {
    private val listeners = mutableListOf<(NetEvent) -> Unit>()
    fun subscribe(listener: (NetEvent) -> Unit) { listeners.add(listener) }
    fun publish(event: NetEvent) { listeners.toList().forEach { it(event) } }
    fun clear() { listeners.clear() }
}
