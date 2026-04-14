object EventBus {
    private val q = mutableListOf<NetEvent>()

    @Synchronized
    fun push(e: NetEvent){ q.add(e) }

    @Synchronized
    fun drain(): List<NetEvent>{
        val c = q.toList()
        q.clear()
        return c
    }
}
