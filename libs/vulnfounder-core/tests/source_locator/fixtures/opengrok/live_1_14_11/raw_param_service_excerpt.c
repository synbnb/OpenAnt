/* Sanitized task-relevant excerpt from the live OpenGrok raw response. */
PARAM_STATIC int OnIncomingConnect(LoopHandle loop, TaskHandle server)
{
    /* unrelated implementation lines omitted */
}

int InitParamService(void)
{
    PARAM_LOGI("InitParamService pipe: %s.", PIPE_NAME);
    CheckAndCreateDir(PIPE_NAME);
    /* unrelated initialization lines omitted */
    info.server = PIPE_NAME;
    info.incomingConnect = OnIncomingConnect;
}
