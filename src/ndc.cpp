/***************************************************************************
                          ndc.cpp  -  class NDC
                             -------------------
    begin                : jeu avr 17 2003
    copyright            : (C) 2003 by Michael CATANZARITI
    email                : mcatan@free.fr
 ***************************************************************************/

/***************************************************************************
 * Copyright (C) The Apache Software Foundation. All rights reserved.      *
 *                                                                         *
 * This software is published under the terms of the Apache Software       *
 * License version 1.1, a copy of which has been included with this        *
 * distribution in the LICENSE.txt file.                                   *
 ***************************************************************************/

#include <log4cxx/ndc.h>

using namespace log4cxx;
using namespace log4cxx::helpers;

NDC::DiagnosticContext::DiagnosticContext(const tstring& message, 
	const DiagnosticContext * parent)
	: message(message)
{
	if (parent != 0)
	{
		fullMessage = parent->fullMessage + ' ' + message;
	} 
	else 
	{
		fullMessage = message;
	}
}

// static member instanciation
ThreadSpecificData NDC::threadSpecificData;

NDC::Stack * NDC::getCurrentThreadStack()
{
	return (Stack *)threadSpecificData.GetData();
}

void NDC::setCurrentThreadStack(NDC::Stack * stack)
{
	threadSpecificData.SetData((void *)stack); 
}

void NDC::clear()
{
	Stack * stack = getCurrentThreadStack();    
	if(stack != 0)
	{
		delete stack;
		setCurrentThreadStack(0);
	} 
}

NDC::Stack * NDC::cloneStack()
{
	Stack * stack = getCurrentThreadStack();
	if(stack != 0)
	{
		return new Stack(*stack);
	}
	else
	{
		return new Stack();
	}
}

void NDC::inherit(NDC::Stack * stack)
{
	if(stack != 0)
	{
		Stack * oldStack = getCurrentThreadStack();
		if(oldStack != 0)
		{
			delete oldStack;
		}
	
		setCurrentThreadStack(stack);
	}
}

tstring NDC::get()
{
	Stack * stack = getCurrentThreadStack();
	if(stack != 0 && !stack->empty())
	{
		return stack->top().fullMessage;
	}
	else
	{
		return tstring();
	}
}

int NDC::getDepth()
{
	Stack * stack = getCurrentThreadStack();
	if(stack == 0)
	{
		return 0;
	}
	else
	{
		return stack->size();
	}
}

tstring NDC::pop()
{
	Stack * stack = getCurrentThreadStack();
	if(stack != 0 && !stack->empty())
	{
		tstring message = stack->top().message;
		stack->pop();
		if (stack->empty())
		{
			delete stack;
			setCurrentThreadStack(0);
		}
		return message;
	}
	else
	{
		return tstring();
	}
}

tstring NDC::peek()
{
	Stack * stack = getCurrentThreadStack();
	if(stack != 0 && !stack->empty())
	{
		return stack->top().message;
	}
	else
	{
		return tstring();
	}
}

void NDC::push(const tstring& message)
{
	Stack * stack = getCurrentThreadStack();

	if (stack == 0)
	{
		stack = new Stack;
		setCurrentThreadStack(stack);
		stack->push(DiagnosticContext(message, 0));
	}
	else if (stack->empty())
	{
		stack->push(DiagnosticContext(message, 0));
	}
	else
	{
		DiagnosticContext& parent = stack->top();
		stack->push(DiagnosticContext(message, &parent));
	}
}

void NDC::remove()
{
	Stack * stack = getCurrentThreadStack();
	if(stack != 0)
	{
		delete stack;
		setCurrentThreadStack(0);
	}
}
