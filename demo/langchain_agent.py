"""A standard LangChain AgentExecutor that refunds Stripe charges through Agentic IAM Proxy."""
import os

from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

from langchain_agentic_iam import SecureAPIWrapper
from _support import AGENTIC_TOKEN, CUSTOMER_ID, ChainPrinter, summarize

# Agentic IAM Proxy: the agent gets a proxy token, never a Stripe key.
stripe = SecureAPIWrapper(
    proxy_base_url="http://localhost:8000/api/v1/proxy",
    agent_token=AGENTIC_TOKEN,
)


@tool
def list_charges(customer_id: str) -> str:
    """List a Stripe customer's most recent charges."""
    return summarize(stripe.get("https://api.stripe.com/v1/charges", params={"customer": customer_id, "limit": 3}))


@tool
def stripe_refund(charge_id: str) -> str:
    """Refund a Stripe charge in full."""
    return summarize(stripe.post("https://api.stripe.com/v1/refunds", data={"charge": charge_id}))


llm = (ChatOpenAI(model="gpt-4o-mini") if os.getenv("OPENAI_API_KEY")
       else ChatGoogleGenerativeAI(model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash")))
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a billing support agent. Look up charges before refunding. "
               "If an action is blocked or denied, say so and stop."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
tools = [list_charges, stripe_refund]
agent_executor = AgentExecutor(agent=create_tool_calling_agent(llm, tools, prompt), tools=tools)

if __name__ == "__main__":
    agent_executor.invoke(
        {"input": f"Customer {CUSTOMER_ID} was double-charged for the $49.99 Pro plan. Refund their latest charge."},
        config={"callbacks": [ChainPrinter()]},
    )
